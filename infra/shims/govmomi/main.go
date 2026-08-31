// Command govmomi is the deliberately-throwaway ESXi provisioning shim
// (D31/D35/D66/D80, doc 15 §1). It stands up and tears down virtual-metal
// Linux host VMs on the ESXi cluster over the govmomi SDK so the host agent's
// nested KVM/libvirt/qcow2 stack (infra/terraform/esxi/BRINGUP.md) can run
// inside them and the rest of the platform treats them as bare metal.
//
// It speaks no protos, imports nothing from go.work, and carries no
// session/VM-lifecycle or per-session networking logic (D66): scope is strictly
// provision + destroy of a virtual-metal host. See README.md.
//
// Build & test standalone: GOWORK=off go {build,vet,test} ./...
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "govmomi-shim: "+err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("a subcommand is required (provision|destroy)")
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "provision":
		return runProvision(ctx, rest)
	case "destroy":
		return runDestroy(ctx, rest)
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `govmomi-shim — provision/destroy ESXi virtual-metal host VMs (D31)

usage:
  govmomi-shim provision [flags]   create + power on a nested-virt host VM (idempotent)
  govmomi-shim destroy  [flags]    power off + destroy a host VM (clean, no-op if absent)

run "govmomi-shim provision -h" or "govmomi-shim destroy -h" for flags.
vCenter endpoint + credentials come from the environment; see README.md.
`)
}

// commonFlags holds the connection + placement inputs shared by both
// subcommands. Connection inputs default from the environment (documented in
// README.md); placement inputs fall back to the datacenter/host/pool/datastore
// defaults the Finder resolves when a path is empty.
type commonFlags struct {
	url        string // GOVC_URL — vCenter SDK endpoint (host or https://host/sdk)
	username   string // GOVC_USERNAME
	password   string // GOVC_PASSWORD
	insecure   bool   // GOVC_INSECURE — skip TLS verification (lab vCenter)
	datacenter string
	datastore  string // NVMe-tier datastore (doc 03 §8); empty => default
	pool       string // resource pool path; empty => default
	host       string // host system path; empty => default (cluster picks)
	folder     string // VM folder path; empty => default
	name       string // VM name (required)
}

func registerCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.url, "url", os.Getenv("GOVC_URL"), "vCenter SDK URL (env GOVC_URL); host or https://host/sdk")
	fs.StringVar(&c.username, "username", os.Getenv("GOVC_USERNAME"), "vCenter username (env GOVC_USERNAME)")
	fs.StringVar(&c.password, "password", os.Getenv("GOVC_PASSWORD"), "vCenter password (env GOVC_PASSWORD)")
	fs.BoolVar(&c.insecure, "insecure", envBool("GOVC_INSECURE"), "skip vCenter TLS verification (env GOVC_INSECURE)")
	fs.StringVar(&c.datacenter, "datacenter", os.Getenv("GOVC_DATACENTER"), "datacenter path (env GOVC_DATACENTER); empty => default")
	fs.StringVar(&c.datastore, "datastore", os.Getenv("GOVC_DATASTORE"), "NVMe-tier datastore name (env GOVC_DATASTORE); empty => default")
	fs.StringVar(&c.pool, "pool", os.Getenv("GOVC_RESOURCE_POOL"), "resource pool path (env GOVC_RESOURCE_POOL); empty => default")
	fs.StringVar(&c.host, "host", os.Getenv("GOVC_HOST"), "host system path (env GOVC_HOST); empty => cluster default")
	fs.StringVar(&c.folder, "folder", os.Getenv("GOVC_FOLDER"), "VM inventory folder path (env GOVC_FOLDER); empty => default")
	fs.StringVar(&c.name, "name", os.Getenv("GOVC_VM"), "virtual-metal host VM name (env GOVC_VM); required")
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	default:
		return false
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
