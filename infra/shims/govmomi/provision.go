package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"
)

// hostSpec is the placement + sizing of a virtual-metal host VM, resolved from
// flags/env. It is the single input to provisionVM, which is shared by the CLI
// (real vCenter) and the vcsim-backed test.
type hostSpec struct {
	datacenter string
	datastore  string // NVMe-tier datastore (doc 03 §8); empty => Finder default
	pool       string
	host       string
	folder     string
	name       string
	vcpus      int32
	memoryMB   int64
	diskGB     int64
	guestID    string // e.g. "otherLinux64Guest"
}

// connect dials vCenter and logs in (if the URL carries user info), returning
// the underlying vim25.Client used by provisionVM/destroyVM. Credentials come
// from flags/env (-username/-password override any userinfo in -url). The caller
// owns logout via the returned func.
func connect(ctx context.Context, c *commonFlags) (*vim25.Client, func(context.Context), error) {
	if c.url == "" {
		return nil, nil, fmt.Errorf("vCenter URL is required (-url or env GOVC_URL)")
	}
	u, err := parseVCenterURL(c.url, c.username, c.password)
	if err != nil {
		return nil, nil, err
	}
	gc, err := govmomi.NewClient(ctx, u, c.insecure)
	if err != nil {
		return nil, nil, fmt.Errorf("connect %s: %w", u.Host, err)
	}
	logout := func(ctx context.Context) { _ = gc.Logout(ctx) }
	return gc.Client, logout, nil
}

// parseVCenterURL normalizes a vCenter endpoint (bare host or full URL) into a
// /sdk URL and layers username/password over any userinfo already present.
func parseVCenterURL(raw, username, password string) (*url.URL, error) {
	s := raw
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse vCenter URL %q: %w", raw, err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/sdk"
	}
	if username != "" {
		if password != "" {
			u.User = url.UserPassword(username, password)
		} else {
			u.User = url.User(username)
		}
	}
	return u, nil
}

// runProvision is the `provision` subcommand: parse flags, connect, provision.
func runProvision(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	var c commonFlags
	registerCommon(fs, &c)
	var spec hostSpec
	var vcpus int
	fs.IntVar(&vcpus, "vcpus", envInt("GOVC_VM_VCPUS", 4), "guest vCPU count (env GOVC_VM_VCPUS)")
	mem := fs.Int64("memoryMB", int64(envInt("GOVC_VM_MEMORY_MB", 16384)), "guest memory in MiB (env GOVC_VM_MEMORY_MB)")
	disk := fs.Int64("diskGB", int64(envInt("GOVC_VM_DISK_GB", 100)), "primary disk size in GiB on the NVMe datastore (env GOVC_VM_DISK_GB)")
	guest := fs.String("guest-id", envStr("GOVC_VM_GUEST_ID", "otherLinux64Guest"), "vSphere guest OS identifier (env GOVC_VM_GUEST_ID)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.name == "" {
		return fmt.Errorf("VM name is required (-name or env GOVC_VM)")
	}

	client, logout, err := connect(ctx, &c)
	if err != nil {
		return err
	}
	defer logout(ctx)

	spec = hostSpec{
		datacenter: c.datacenter,
		datastore:  c.datastore,
		pool:       c.pool,
		host:       c.host,
		folder:     c.folder,
		name:       c.name,
		vcpus:      int32(vcpus),
		memoryMB:   *mem,
		diskGB:     *disk,
		guestID:    *guest,
	}

	vm, created, err := provisionVM(ctx, client, spec)
	if err != nil {
		return err
	}
	verb := "already present"
	if created {
		verb = "created"
	}
	fmt.Printf("provisioned virtual-metal host %q (%s, powered on): %s\n", spec.name, verb, vm.Reference())
	return nil
}

// provisionVM idempotently stands up a nested-virt virtual-metal host VM and
// powers it on. If a VM of spec.name already exists it is returned as-is
// (created=false) — repeatable by design. The created VM exposes
// hardware-assisted virtualization to the guest (NestedHVEnabled=true — the
// property that makes /dev/kvm appear, BRINGUP.md) and lands its disk on the
// requested NVMe-tier datastore.
//
// It is the shared core of the CLI and the vcsim test; it takes a vim25.Client
// so the simulator can drive it without credentials or a network.
func provisionVM(ctx context.Context, client *vim25.Client, spec hostSpec) (*object.VirtualMachine, bool, error) {
	finder := find.NewFinder(client, true)

	dc, err := finder.DatacenterOrDefault(ctx, spec.datacenter)
	if err != nil {
		return nil, false, fmt.Errorf("datacenter %q: %w", spec.datacenter, err)
	}
	finder.SetDatacenter(dc)

	// Idempotency: a same-named VM already in inventory satisfies provision.
	if existing, err := finder.VirtualMachine(ctx, spec.name); err == nil {
		return existing, false, nil
	} else if _, ok := err.(*find.NotFoundError); !ok {
		return nil, false, fmt.Errorf("look up VM %q: %w", spec.name, err)
	}

	ds, err := finder.DatastoreOrDefault(ctx, spec.datastore)
	if err != nil {
		return nil, false, fmt.Errorf("datastore %q (NVMe tier): %w", spec.datastore, err)
	}
	pool, err := finder.ResourcePoolOrDefault(ctx, spec.pool)
	if err != nil {
		return nil, false, fmt.Errorf("resource pool %q: %w", spec.pool, err)
	}
	var host *object.HostSystem
	if spec.host != "" {
		if host, err = finder.HostSystem(ctx, spec.host); err != nil {
			return nil, false, fmt.Errorf("host %q: %w", spec.host, err)
		}
	}
	folder, err := finder.FolderOrDefault(ctx, spec.folder)
	if err != nil {
		return nil, false, fmt.Errorf("folder %q: %w", spec.folder, err)
	}

	configSpec := buildConfigSpec(spec, ds.Name())

	task, err := folder.CreateVM(ctx, configSpec, pool, host)
	if err != nil {
		return nil, false, fmt.Errorf("create VM %q: %w", spec.name, err)
	}
	info, err := task.WaitForResult(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("create VM %q: %w", spec.name, err)
	}
	vm := object.NewVirtualMachine(client, info.Result.(types.ManagedObjectReference))

	powerOn, err := vm.PowerOn(ctx)
	if err != nil {
		return vm, true, fmt.Errorf("power on %q: %w", spec.name, err)
	}
	if _, err := powerOn.WaitForResult(ctx, nil); err != nil {
		return vm, true, fmt.Errorf("power on %q: %w", spec.name, err)
	}
	return vm, true, nil
}

// buildConfigSpec assembles the VirtualMachineConfigSpec for a virtual-metal
// host: nested HV on (expose hardware-assisted virt to the guest), sizing from
// spec, files + a thin-provisioned primary disk on the named NVMe datastore.
func buildConfigSpec(spec hostSpec, datastoreName string) types.VirtualMachineConfigSpec {
	nestedHV := true
	dsRef := fmt.Sprintf("[%s]", datastoreName)

	scsi := &types.VirtualLsiLogicController{
		VirtualSCSIController: types.VirtualSCSIController{
			SharedBus: types.VirtualSCSISharingNoSharing,
			VirtualController: types.VirtualController{
				BusNumber: 0,
				VirtualDevice: types.VirtualDevice{
					Key: -100,
				},
			},
		},
	}

	disk := &types.VirtualDisk{
		CapacityInKB: spec.diskGB * 1024 * 1024,
		VirtualDevice: types.VirtualDevice{
			Key:           -101,
			ControllerKey: scsi.Key,
			UnitNumber:    types.NewInt32(0),
			Backing: &types.VirtualDiskFlatVer2BackingInfo{
				DiskMode:        string(types.VirtualDiskModePersistent),
				ThinProvisioned: types.NewBool(true),
				VirtualDeviceFileBackingInfo: types.VirtualDeviceFileBackingInfo{
					FileName: dsRef, // datastore-relative; vSphere fills the path
				},
			},
		},
	}

	return types.VirtualMachineConfigSpec{
		Name:     spec.name,
		GuestId:  spec.guestID,
		NumCPUs:  spec.vcpus,
		MemoryMB: spec.memoryMB,
		Flags: &types.VirtualMachineFlagInfo{
			// The one property this whole shim exists to set: expose
			// hardware-assisted virtualization to the guest so nested KVM
			// (/dev/kvm) works (D31, BRINGUP.md prerequisites).
			VirtualExecUsage: string(types.VirtualMachineFlagInfoVirtualExecUsageHvAuto),
		},
		NestedHVEnabled: &nestedHV,
		Files: &types.VirtualMachineFileInfo{
			VmPathName: dsRef, // place config + disk on the NVMe datastore
		},
		DeviceChange: []types.BaseVirtualDeviceConfigSpec{
			&types.VirtualDeviceConfigSpec{
				Operation: types.VirtualDeviceConfigSpecOperationAdd,
				Device:    scsi,
			},
			&types.VirtualDeviceConfigSpec{
				Operation:     types.VirtualDeviceConfigSpecOperationAdd,
				FileOperation: types.VirtualDeviceConfigSpecFileOperationCreate,
				Device:        disk,
			},
		},
	}
}
