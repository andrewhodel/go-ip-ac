## installation

```
cd go/src
git clone github.com/andrewhodel/go-ip-ac
```

## usage

Run `examples/example.go`

```go
var ip_ac ipac.Ipac

ipac.Init(&ip_ac)

// set authorization status of an IP
// logout
ipac.ModifyAuth(&ip_ac, "logout", "127.0.0.1")
// invalid login credentials
ipac.ModifyAuth(&ip_ac, "invalid_login", "127.0.0.1")
// authorized (valid login credentials)
ipac.ModifyAuth(&ip_ac, "valid_login", "127.0.0.1")

// test authorization status of an IP
// this can be called every time there is a new IP connection
// if you want to block the IP connection in the application, it is not required if you are using iptables/ip6tables
var status = ipac.TestIpAllowed(&ip_ac, "127.0.0.1")
fmt.Printf("TestIpAllowed 127.0.0.1: %t\n", status)

// test if you should warn connections from an IP
// this must be called if you want to warn connections from the application that more requests forces a block
var warn = ipac.TestIpWarn(&ip_ac, "127.0.0.1")
fmt.Printf("TestIpWarn 127.0.0.1: %t\n", warn)

// return details of a specific ip address
var ip_details = ipac.IpDetails(&ip_ac, "127.0.0.1")
fmt.Printf("IpDetails 127.0.0.1: %+v\n", ip_details)
```

## default options

Set these in the object {} passed as the first argument to `ipac.Init()` if you want to change the defaults shown here.

```go
// default configurable options

// how many seconds between each iteration of the cleanup loop
o.CleanupLoopSeconds = 60

// how many seconds to ban/block entities for
o.BlockForSeconds = 60 * 60

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
// display a denial of service warning to the IP
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

// event notification closure
o.NotifyClosure = func(event string, info string, ips []string) {

	// event is a string of ips_blocked, ips_exceeded_absurd_auth_attempts or subnet_blocked
	// info is a string about the event
	// ips is a list of ip addresses related to the event

}

// enable/disable the firewall
o.NeverBlock = false
```

## counts

You may want the total counts.

```go
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

In this module there exists support of `iptables` and `ip6tables` in Linux.

There is structure to support any OS and firewall that Go supports.

There is also structure to support API calls to network or hosting providers, like AWS.

## license

Code is licensed MIT

Copyright 2022 Andrew Hodel
