package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"
)

// runDestroy is the `destroy` subcommand: parse flags, connect, destroy.
func runDestroy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("destroy", flag.ContinueOnError)
	var c commonFlags
	registerCommon(fs, &c)
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

	found, err := destroyVM(ctx, client, c.datacenter, c.name)
	if err != nil {
		return err
	}
	if !found {
		fmt.Printf("virtual-metal host %q not present; nothing to destroy\n", c.name)
		return nil
	}
	fmt.Printf("destroyed virtual-metal host %q\n", c.name)
	return nil
}

// destroyVM cleanly tears down a virtual-metal host VM: find -> power off (if on)
// -> destroy. Returns found=false (and no error) when no such VM exists, so the
// subcommand is a safe no-op against already-clean inventory. Shared by the CLI
// and the vcsim test; takes a vim25.Client.
func destroyVM(ctx context.Context, client *vim25.Client, datacenter, name string) (bool, error) {
	finder := find.NewFinder(client, true)
	dc, err := finder.DatacenterOrDefault(ctx, datacenter)
	if err != nil {
		return false, fmt.Errorf("datacenter %q: %w", datacenter, err)
	}
	finder.SetDatacenter(dc)

	vm, err := finder.VirtualMachine(ctx, name)
	if err != nil {
		if _, ok := err.(*find.NotFoundError); ok {
			return false, nil
		}
		return false, fmt.Errorf("look up VM %q: %w", name, err)
	}

	if err := powerOffIfOn(ctx, vm); err != nil {
		return true, err
	}

	task, err := vm.Destroy(ctx)
	if err != nil {
		return true, fmt.Errorf("destroy VM %q: %w", name, err)
	}
	if _, err := task.WaitForResult(ctx, nil); err != nil {
		return true, fmt.Errorf("destroy VM %q: %w", name, err)
	}
	return true, nil
}

// powerOffIfOn powers a VM off when it is powered on, ignoring the
// already-off race. A powered-on VM cannot be destroyed.
func powerOffIfOn(ctx context.Context, vm *object.VirtualMachine) error {
	state, err := vm.PowerState(ctx)
	if err != nil {
		return fmt.Errorf("power state: %w", err)
	}
	if state != types.VirtualMachinePowerStatePoweredOn {
		return nil
	}
	task, err := vm.PowerOff(ctx)
	if err != nil {
		return fmt.Errorf("power off: %w", err)
	}
	if _, err := task.WaitForResult(ctx, nil); err != nil {
		return fmt.Errorf("power off: %w", err)
	}
	return nil
}
