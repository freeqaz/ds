package main

import (
	"context"
	"strings"
	"testing"

	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// The simulator's default VPX inventory names its datastore LocalDS_0; we treat
// it as the NVMe-tier datastore for the test (a real run names the actual NVMe
// datastore via -datastore / GOVC_DATASTORE).
const simNVMeDatastore = "LocalDS_0"

func testSpec(name string) hostSpec {
	return hostSpec{
		datastore: simNVMeDatastore,
		name:      name,
		vcpus:     4,
		memoryMB:  16384,
		diskGB:    100,
		guestID:   "otherLinux64Guest",
	}
}

// TestProvisionDestroy drives the shared provision/destroy core against the
// in-process vCenter simulator (no credentials, no network). It proves a fresh
// virtual-metal host can be stood up and torn down by the same calls the CLI
// makes, and asserts the load-bearing config: nested HV exposed to the guest
// (the /dev/kvm property) + disk on the requested NVMe datastore.
func TestProvisionDestroy(t *testing.T) {
	// A single-cluster datacenter (no standalone hosts) so the Finder's
	// "default" datacenter/pool/datastore/folder resolve unambiguously — the
	// shape of the real single-cluster ESXi target the shim provisions into.
	model := simulator.VPX()
	model.Host = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-host-0"
		spec := testSpec(name)

		vm, created, err := provisionVM(ctx, c, spec)
		if err != nil {
			t.Fatalf("provisionVM: %v", err)
		}
		if !created {
			t.Fatalf("first provision should report created=true")
		}

		// VM exists in inventory.
		finder := find.NewFinder(c, true)
		dc, err := finder.DefaultDatacenter(ctx)
		if err != nil {
			t.Fatalf("default datacenter: %v", err)
		}
		finder.SetDatacenter(dc)
		if _, err := finder.VirtualMachine(ctx, name); err != nil {
			t.Fatalf("VM %q not found after provision: %v", name, err)
		}

		// Read back config and assert the nested-virt + sizing properties the
		// create spec carried.
		var moVM mo.VirtualMachine
		if err := vm.Properties(ctx, vm.Reference(),
			[]string{"config", "runtime.powerState", "datastore"}, &moVM); err != nil {
			t.Fatalf("read VM properties: %v", err)
		}
		if moVM.Config == nil {
			t.Fatal("VM has no config")
		}
		if moVM.Config.NestedHVEnabled == nil || !*moVM.Config.NestedHVEnabled {
			t.Errorf("NestedHVEnabled = %v, want true (nested virt must be exposed to the guest)", moVM.Config.NestedHVEnabled)
		}
		if moVM.Config.GuestId != spec.guestID {
			t.Errorf("GuestId = %q, want %q", moVM.Config.GuestId, spec.guestID)
		}
		if got := moVM.Config.Hardware.NumCPU; got != spec.vcpus {
			t.Errorf("NumCPU = %d, want %d", got, spec.vcpus)
		}
		if got := moVM.Config.Hardware.MemoryMB; int64(got) != spec.memoryMB {
			t.Errorf("MemoryMB = %d, want %d", got, spec.memoryMB)
		}

		// Powered on.
		if moVM.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOn {
			t.Errorf("power state = %s, want poweredOn", moVM.Runtime.PowerState)
		}

		// Disk present at the requested size, on the requested NVMe datastore.
		assertDiskOnDatastore(ctx, t, c, vm, moVM, spec)

		// Idempotency: a second provision returns the existing VM, not a new one.
		vm2, created2, err := provisionVM(ctx, c, spec)
		if err != nil {
			t.Fatalf("second provisionVM: %v", err)
		}
		if created2 {
			t.Errorf("second provision created a new VM; want idempotent (created=false)")
		}
		if vm2.Reference() != vm.Reference() {
			t.Errorf("second provision returned a different VM: %v != %v", vm2.Reference(), vm.Reference())
		}

		// Destroy and assert it is gone.
		found, err := destroyVM(ctx, c, "", name)
		if err != nil {
			t.Fatalf("destroyVM: %v", err)
		}
		if !found {
			t.Errorf("destroyVM reported not-found for an existing VM")
		}
		if _, err := finder.VirtualMachine(ctx, name); err == nil {
			t.Errorf("VM %q still present after destroy", name)
		} else if _, ok := err.(*find.NotFoundError); !ok {
			t.Errorf("unexpected error looking up destroyed VM: %v", err)
		}

		// Destroy is a clean no-op the second time.
		found2, err := destroyVM(ctx, c, "", name)
		if err != nil {
			t.Fatalf("second destroyVM: %v", err)
		}
		if found2 {
			t.Errorf("second destroy reported found=true for an absent VM")
		}
	}, model)
}

// TestProvisionBadDatastore asserts that provisioning into a non-existent
// datastore name fails with the clear wrapped error and — load-bearing — leaves
// NO orphaned VM in inventory (the datastore lookup is gated before CreateVM, so
// a typo'd NVMe tier never half-creates a host).
func TestProvisionBadDatastore(t *testing.T) {
	model := simulator.VPX()
	model.Host = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-bad-ds"
		spec := testSpec(name)
		spec.datastore = "no-such-datastore"

		_, created, err := provisionVM(ctx, c, spec)
		if err == nil {
			t.Fatalf("provisionVM into a non-existent datastore should fail; got created=%v, nil error", created)
		}
		// The wrapper makes the operator-facing cause unambiguous: it names the
		// datastore and the NVMe tier (the `datastore %q (NVMe tier): %w` wrap).
		if !strings.Contains(err.Error(), `datastore "no-such-datastore" (NVMe tier)`) {
			t.Errorf("error = %q, want it to carry the datastore wrapper", err.Error())
		}
		if created {
			t.Errorf("created = true on a failed provision; want false")
		}
		assertNoOrphan(ctx, t, c, name)
	}, model)
}

// TestProvisionBadResourcePool asserts that provisioning into a non-existent
// resource pool name fails with the clear wrapped error and leaves no orphaned
// VM in inventory. The datastore is valid here, so this pins the pool-lookup
// gate specifically (it runs after the datastore lookup, still before CreateVM).
func TestProvisionBadResourcePool(t *testing.T) {
	model := simulator.VPX()
	model.Host = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-bad-pool"
		spec := testSpec(name)
		spec.pool = "no-such-resource-pool"

		_, created, err := provisionVM(ctx, c, spec)
		if err == nil {
			t.Fatalf("provisionVM into a non-existent resource pool should fail; got created=%v, nil error", created)
		}
		if !strings.Contains(err.Error(), `resource pool "no-such-resource-pool"`) {
			t.Errorf("error = %q, want it to carry the resource-pool wrapper", err.Error())
		}
		if created {
			t.Errorf("created = true on a failed provision; want false")
		}
		assertNoOrphan(ctx, t, c, name)
	}, model)
}

// TestDestroyPoweredOnVM pins the powerOffIfOn invariant: a freshly provisioned
// host is powered on, and a powered-on VM cannot be destroyed until it is
// powered off. The test confirms the VM is poweredOn going in (so the power-off
// leg is genuinely exercised, not skipped), then destroys and asserts the VM is
// gone.
func TestDestroyPoweredOnVM(t *testing.T) {
	model := simulator.VPX()
	model.Host = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-poweron-destroy"
		spec := testSpec(name)

		vm, created, err := provisionVM(ctx, c, spec)
		if err != nil {
			t.Fatalf("provisionVM: %v", err)
		}
		if !created {
			t.Fatalf("first provision should report created=true")
		}

		// Going in the VM must be poweredOn, so destroyVM's powerOffIfOn leg is
		// the path under test (an already-off VM would skip it).
		state, err := vm.PowerState(ctx)
		if err != nil {
			t.Fatalf("power state: %v", err)
		}
		if state != types.VirtualMachinePowerStatePoweredOn {
			t.Fatalf("VM power state = %s before destroy, want poweredOn", state)
		}

		found, err := destroyVM(ctx, c, "", name)
		if err != nil {
			t.Fatalf("destroyVM of a powered-on VM: %v (power-off-then-destroy must succeed)", err)
		}
		if !found {
			t.Errorf("destroyVM reported not-found for an existing powered-on VM")
		}

		finder := find.NewFinder(c, true)
		dc, err := finder.DefaultDatacenter(ctx)
		if err != nil {
			t.Fatalf("default datacenter: %v", err)
		}
		finder.SetDatacenter(dc)
		if _, err := finder.VirtualMachine(ctx, name); err == nil {
			t.Errorf("VM %q still present after destroy of powered-on host", name)
		} else if _, ok := err.(*find.NotFoundError); !ok {
			t.Errorf("unexpected error looking up destroyed VM: %v", err)
		}
	}, model)
}

// TestPowerOffIfOnTransitionsThenIsIdempotent pins powerOffIfOn directly: it
// powers a poweredOn VM off (the destroy precondition) and is a clean no-op on
// an already-off VM (the already-off race the comment guards against).
func TestPowerOffIfOnTransitionsThenIsIdempotent(t *testing.T) {
	model := simulator.VPX()
	model.Host = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-poweroff-invariant"
		spec := testSpec(name)

		vm, _, err := provisionVM(ctx, c, spec)
		if err != nil {
			t.Fatalf("provisionVM: %v", err)
		}

		if err := powerOffIfOn(ctx, vm); err != nil {
			t.Fatalf("powerOffIfOn on a powered-on VM: %v", err)
		}
		state, err := vm.PowerState(ctx)
		if err != nil {
			t.Fatalf("power state after powerOffIfOn: %v", err)
		}
		if state != types.VirtualMachinePowerStatePoweredOff {
			t.Errorf("power state = %s after powerOffIfOn, want poweredOff", state)
		}

		// Idempotent: a second call on an already-off VM is a clean no-op.
		if err := powerOffIfOn(ctx, vm); err != nil {
			t.Errorf("powerOffIfOn on an already-off VM should be a no-op, got: %v", err)
		}
	}, model)
}

// The simulator's default VPX datacenter (DC0) with Model.Host >= 1 creates
// standalone hosts named DC0_H<n>; DC0_H0 is the first standalone host, and its
// ComputeResource name is what finder.HostSystem resolves against.
const simStandaloneHost = "DC0_H0"

// TestProvisionExplicitHost drives the spec.host != "" placement branch in
// provisionVM end to end against a VPX model that carries a standalone host
// (Model.Host = 1). With spec.host set, provisionVM resolves the HostSystem and
// passes it (non-nil) to CreateVM, so the VM must land on exactly that host — the
// branch every other provision test leaves uncovered by zeroing Model.Host. The
// test asserts the VM's runtime.host matches the resolved standalone host's
// reference (the placement actually took effect, not just that create succeeded).
func TestProvisionExplicitHost(t *testing.T) {
	// A single standalone host, no cluster, one datastore: DC0_H0 with LocalDS_0.
	// This keeps the default resource pool / datastore / folder unambiguous while
	// giving the explicit-host lookup exactly one target to resolve.
	model := simulator.VPX()
	model.Host = 1
	model.Cluster = 0
	model.ClusterHost = 0
	model.Machine = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-explicit-host"
		spec := testSpec(name)
		spec.host = simStandaloneHost

		vm, created, err := provisionVM(ctx, c, spec)
		if err != nil {
			t.Fatalf("provisionVM with explicit host %q: %v", spec.host, err)
		}
		if !created {
			t.Fatalf("first provision should report created=true")
		}

		// Resolve the host we asked for, so we can compare references.
		finder := find.NewFinder(c, true)
		dc, err := finder.DefaultDatacenter(ctx)
		if err != nil {
			t.Fatalf("default datacenter: %v", err)
		}
		finder.SetDatacenter(dc)
		wantHost, err := finder.HostSystem(ctx, spec.host)
		if err != nil {
			t.Fatalf("resolve host %q: %v", spec.host, err)
		}

		// The VM must be placed on exactly the requested host.
		var moVM mo.VirtualMachine
		if err := vm.Properties(ctx, vm.Reference(), []string{"runtime.host"}, &moVM); err != nil {
			t.Fatalf("read VM runtime.host: %v", err)
		}
		if moVM.Runtime.Host == nil {
			t.Fatal("VM has no runtime.host after explicit-host placement")
		}
		if *moVM.Runtime.Host != wantHost.Reference() {
			t.Errorf("VM placed on host %v, want explicit host %q (%v)",
				*moVM.Runtime.Host, spec.host, wantHost.Reference())
		}
	}, model)
}

// TestProvisionBadHost pins the explicit-host failure leg: a non-existent host
// name fails with the clear `host %q: %w` wrapper and leaves no orphaned VM (the
// host lookup is gated before CreateVM, so a typo'd -host never half-creates).
func TestProvisionBadHost(t *testing.T) {
	model := simulator.VPX()
	model.Host = 1
	model.Cluster = 0
	model.ClusterHost = 0
	model.Machine = 0

	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		const name = "ds-vmetal-bad-host"
		spec := testSpec(name)
		spec.host = "no-such-host"

		_, created, err := provisionVM(ctx, c, spec)
		if err == nil {
			t.Fatalf("provisionVM onto a non-existent host should fail; got created=%v, nil error", created)
		}
		if !strings.Contains(err.Error(), `host "no-such-host"`) {
			t.Errorf("error = %q, want it to carry the host wrapper", err.Error())
		}
		if created {
			t.Errorf("created = true on a failed provision; want false")
		}
		assertNoOrphan(ctx, t, c, name)
	}, model)
}

// assertNoOrphan fails the test if a VM of the given name exists in the default
// datacenter — the no-orphaned-VM guarantee for a failed provision.
func assertNoOrphan(ctx context.Context, t *testing.T, c *vim25.Client, name string) {
	t.Helper()
	finder := find.NewFinder(c, true)
	dc, err := finder.DefaultDatacenter(ctx)
	if err != nil {
		t.Fatalf("default datacenter: %v", err)
	}
	finder.SetDatacenter(dc)
	if _, err := finder.VirtualMachine(ctx, name); err == nil {
		t.Errorf("orphaned VM %q left in inventory after a failed provision", name)
	} else if _, ok := err.(*find.NotFoundError); !ok {
		t.Errorf("unexpected error checking for orphaned VM %q: %v", name, err)
	}
}

// assertDiskOnDatastore verifies the VM has a virtual disk of the requested
// capacity and that the VM's datastore set resolves to the requested NVMe
// datastore name.
func assertDiskOnDatastore(ctx context.Context, t *testing.T, c *vim25.Client, vm *object.VirtualMachine, moVM mo.VirtualMachine, spec hostSpec) {
	t.Helper()

	devices := object.VirtualDeviceList(moVM.Config.Hardware.Device)
	disks := devices.SelectByType((*types.VirtualDisk)(nil))
	if len(disks) == 0 {
		t.Fatal("VM has no virtual disk")
	}
	disk := disks[0].(*types.VirtualDisk)
	wantKB := spec.diskGB * 1024 * 1024
	if disk.CapacityInKB != wantKB {
		t.Errorf("disk capacity = %d KB, want %d KB (%d GiB)", disk.CapacityInKB, wantKB, spec.diskGB)
	}

	// The VM's datastore set must include the requested NVMe datastore.
	if len(moVM.Datastore) == 0 {
		t.Fatal("VM is on no datastore")
	}
	foundNVMe := false
	for _, ref := range moVM.Datastore {
		ds := object.NewDatastore(c, ref)
		var moDS mo.Datastore
		if err := ds.Properties(ctx, ref, []string{"name"}, &moDS); err != nil {
			t.Fatalf("read datastore name: %v", err)
		}
		if moDS.Name == spec.datastore {
			foundNVMe = true
		}
	}
	if !foundNVMe {
		t.Errorf("VM not placed on requested NVMe datastore %q (datastores: %d)", spec.datastore, len(moVM.Datastore))
	}
}
