## installation

**Requires** this Go Module to be in `$HOME/go/src/github.com/andrewhodel/go-ip-ac` to work with `iptables` unless you set the `ModuleDirectory` option.

```
GO111MODULE=off go get github.com/andrewhodel/go-ip-ac
```

Run your Go program with `GO111MODULE=off go run program.go`

## usage

Run `examples/example.go`

```
var ip_ac ipac.Ipac

// notify closure, use to send firewall notifications to admins
ip_ac.NotifyClosure = func(message_id int, info string, ips []string) {

    // message_id is an int specifying the message id
	// info is a string about the event
	// ips is a list of ip addresses related to the event

}

ipac.Init(&ip_ac)

// set authorization status for an IP
// logout
ipac.ModifyAuth(&ip_ac, 0, "127.0.0.1")
// invalid login credentials
ipac.ModifyAuth(&ip_ac, 1, "127.0.0.1")
// authorized (valid login credentials)
ipac.ModifyAuth(&ip_ac, 2, "127.0.0.1")

// test authorization status for an IP
// this needs to be called every time there is a new IP connection
var status = ipac.TestIpAllowed(&ip_ac, "127.0.0.1")
fmt.Printf("TestIpAllowed 127.0.0.1: %t\n", status)

// test if you should warn users from an IP
var warn = ipac.TestIpWarn(&ip_ac, "127.0.0.1")
fmt.Printf("TestIpWarn 127.0.0.1: %t\n", warn)

// return details for a specific ip address
var ip_details = ipac.IpDetails(&ip_ac, "127.0.0.1")
fmt.Printf("IpDetails 127.0.0.1: %+v\n", ip_details)
```

## default options

Set these in the object {} passed as the first argument to `ipac.Init()` if you want to change the defaults shown here.

```
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.CleanupLoopSeconds = 60

// how many seconds to ban/block entities for
o.BlockForSeconds = 60 * 60 * 24

// maximum depth to classify IPv6 is
// 64 bits of a network prefix and 64 bits of an interface identifier
// 64 bits is 4 groups that are 16 bits each
o.BlockIpv6SubnetsGroupDepth = 4

// the number of IP bans within a subnet group required for a subnet group to be blocked
o.BlockIpv6SubnetsBreach = 40
// number of lowest level subnets to block
// multiplied by itself for each step back
//
// example values: depth 4 and breach 40
// example ip: 2404:3c00:c140:b3c0:5d43:d92e:7b4f:5d52
//
// 2404* blocked at 40*40*40*40 ips
// 2404:3c00* blocked at 40*40*40 ips
// 2404:3c00:c140* blocked at 40*40 ips
// 2404:3c00:c140:b3c0* blocked at 40 ips

// warn after N unauthorized new connections
// requests from these IP addresses should
// display a denial of service warning for the IP
// in the user interface
o.WarnAfterNewConnections = 80

// block after N unauthorized new connections
o.BlockAfterNewConnections = 600

// block after N invalid authorization attempts
// this prevents login guessing many times from the same IP address
o.BlockAfterUnauthedAttempts = 30

// notify after N absurd auth attempts
// failed authorization attempts after the IP has been authorized
o.NotifyAfterAbsurdAuthAttempts = 20

// IP addresses were blocked
// IP addresses exceeded the o.NotifyAfterAbsurdAuthAttempts limit
// IPv6 subnet was blocked

// set to a function to receive firewall events and ip information
// leave as nil to not receive this information
o.NotifyClosure = func(message_id int, info string, ips []string) {

    // message_id is an int specifying the message id
	// info is a string about the event
	// ips is a list of ip addresses related to the event

}

// go-ip-ac module path (required if not in $HOME/go
o.ModuleDirectory = "/path/to/module"

// enable/disable the firewall
o.NeverBlock = false
```

## counts

You may want the total counts.

```
// count of IP Addresses that have connected in the last ip_ac.block_for_seconds
ip_ac.TotalCount

// count of IP Addresses that are blocked
ip_ac.BlockedCount

// count of IP Addresses that are warned
ip_ac.WarnCount

// count of subnets that are blocked
ip_ac.BlockedSubnetCount
```

If you want to read each of the IP addresses, use `.Lock()` and `.Unlock()` of the `Ipac` struct usually named `o` that you set the options with.

## firewall support

In this module there exists support for `iptables` on Linux.

There is structure for supporting any OS and firewall that Go supports.

There is also structure for supporting API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
