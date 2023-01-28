/*
Copyright 2022 Andrew Hodel
	andrewhodel@gmail.com
LICENSE MIT
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package ipac

import (
	"os"
	"os/exec"
	"bytes"
	"time"
	//"fmt"
	"runtime"
	"sync"
	"strings"
	"math"
)

type Ip struct {
	Addr				string
	Authed				bool
	Warn				bool
	Blocked				bool
	LastAccess			int
	LastAuth			int
	UnauthedNewConnections		int
	UnauthedAttempts		int
	AbsurdAuthAttempts		int
}

type Ipv6Subnet struct {
	Group				string
	IpBans				int
	BlockedTs			int
}

type notify_func func(string, []string)

type Ipac struct {
	CleanupLoopSeconds		int
	BlockForSeconds			int
	BlockIpv6SubnetsGroupDepth	int
	BlockIpv6SubnetsBreach		int
	WarnAfterNewConnections		int
	WarnAfterUnauthedAttempts	int
	BlockAfterNewConnections	int
	BlockAfterUnauthedAttempts	int
	NotifyAfterAbsurdAuthAttempts	int
	NotifyClosure			notify_func
	Purge				bool
	LastCleanup			int
	LastNotifyAbsurd		int
	NextNotifyBlockedIps		[]string
	NextNotifyAbsurdIps		[]string
	Ips				[]Ip
	Ipv6Subnets			[]Ipv6Subnet
	TotalCount			int
	BlockedCount			int
	WarnCount			int
	BlockedSubnetCount		int
	ModuleDirectory			string
	NeverBlock			bool
}

var ipac_mutex = &sync.Mutex{}

func comm(o *Ipac, s string) (string, string) {

	// the command.sh file is required
	var module_directory = ""
	if (o.ModuleDirectory != "") {
		// use the configured module directory
		module_directory = o.ModuleDirectory
	} else {
		// use the home directory and go 111 module path
		module_directory = os.Getenv("HOME") + "/go/src/github.com/andrewhodel/go-ip-ac/"
	}

	cmd := exec.Command(module_directory + "command.sh", s)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	_ = cmd.Run()

	if (len(stderr.String()) > 0) {
		//fmt.Printf("comm() stderr for `%s`\n\t%s\n", s, stderr.String())
	}

	return out.String(), stderr.String()

}

func Init(o *Ipac) {

	// remove existing firewall rules created by go-ip-ac
	if (runtime.GOOS == "linux") {
		// first flush the goipac chain
		comm(o, "sudo iptables -F goipac")
		// then delete the chain
		comm(o, "sudo iptables -X goipac")
		// then add the chain
		comm(o, "sudo iptables -N goipac")
	}

	// set options passed to init as default options
	if (o.CleanupLoopSeconds == 0) {
		o.CleanupLoopSeconds = 60
	}
	if (o.BlockForSeconds == 0) {
		o.BlockForSeconds = 60 * 60 * 24
	}
	if (o.BlockIpv6SubnetsGroupDepth == 0) {
		o.BlockIpv6SubnetsGroupDepth = 4
	}
	if (o.BlockIpv6SubnetsBreach == 0) {
		o.BlockIpv6SubnetsBreach = 40
	}
	if (o.WarnAfterNewConnections == 0) {
		o.WarnAfterNewConnections = 80
	}
	if (o.WarnAfterUnauthedAttempts == 0) {
		o.WarnAfterUnauthedAttempts = 5
	}
	if (o.BlockAfterNewConnections == 0) {
		o.BlockAfterNewConnections = 600
	}
	if (o.BlockAfterUnauthedAttempts == 0) {
		o.BlockAfterUnauthedAttempts = 30
	}
	if (o.NotifyAfterAbsurdAuthAttempts == 0) {
		o.NotifyAfterAbsurdAuthAttempts = 20
	}
	o.Purge = false

	//fmt.Printf("default options: %+v\n", o)

	o.LastCleanup = int(time.Now().Unix())
	o.LastNotifyAbsurd = int(time.Now().Unix()) - o.BlockForSeconds

	go clean(o)

}

func clean(o *Ipac) {

	time.Sleep(time.Duration(o.CleanupLoopSeconds) * time.Second)

	// consider the time since the last interval
	var seconds_since_last_cleanup = int(time.Now().Unix()) - o.LastCleanup

	var expire_older_than = o.BlockForSeconds - seconds_since_last_cleanup

	var ctotal = 0
	var cblocked = 0
	var cwarn = 0
	var cblocked_subnet = 0

	ipac_mutex.Lock()

	// show all the Ipac data
	//fmt.Println("clean() iteration", "number of Ips", len(o.Ips), o)

	if (o.Purge == true) {

		// remove the ips
		o.Ips = nil
		// remove the IPv6 subnets
		o.Ipv6Subnets = nil

		// reset o.Purge
		o.Purge = false

		// unlock the mutex
		ipac_mutex.Unlock()

		//fmt.Println("Purge completed")

		// run clean again
		go clean(o)

		// exit this thread
		return

	}

	// clear expired ips
	for i := len(o.Ips)-1; i >= 0; i-- {

		var entry = o.Ips[i]

		var age_of_ip = int(time.Now().Unix()) - entry.LastAccess

		if (age_of_ip > expire_older_than) {

			// unblock the ip at the OS level
			modify_ip_block_os(o, false, entry)

			// delete the ip
			copy(o.Ips[i:], o.Ips[i+1:]) // Shift a[i+1:] left one index.
			o.Ips = o.Ips[:len(o.Ips)-1]

		} else {

			// this ip was not deleted, count it
			ctotal += 1
			if (entry.Blocked == true) {
				cblocked += 1
			}
			if (entry.Warn == true) {
				cwarn += 1
			}

		}

	}

	// update the ipac object
	o.TotalCount = ctotal
	o.BlockedCount = cblocked
	o.WarnCount = cwarn

	// update the last cleanup
	o.LastCleanup = int(time.Now().Unix())

	// handle subnet group bans
	for i := len(o.Ipv6Subnets)-1; i >= 0; i-- {

		if (o.Ipv6Subnets[i].BlockedTs == 0) {

			// this subnet group is blocked
			// test if the block should expire

			var age_of_ban = int(time.Now().Unix()) - o.Ipv6Subnets[i].BlockedTs

			if (age_of_ban > expire_older_than) {
				// unblock this subnet group
				ipv6_modify_subnet_block_os(o, false, o.Ipv6Subnets[i].Group)
				// delete it
				copy(o.Ipv6Subnets[i:], o.Ipv6Subnets[i+1:]) // Shift a[i+1:] left one index.
				o.Ipv6Subnets = o.Ipv6Subnets[:len(o.Ipv6Subnets)-1]
			} else {
				// increment the blocked subnet count for this clean loop iteration
				cblocked_subnet += 1
			}

			// this group is already blocked
			continue

		}

		// calculate the number of banned ips required for this prefix to be blocked
		// BlockIpv6SubnetsGroupDepth = 4
		// BlockIpv6SubnetsBreach = 40
		// pow(40, 4 - num_of_groups + 1)
		// ffff = pow(40, 4)
		// ffff:ffff = pow(40, 3)
		// ffff:ffff:ffff = pow(40, 2)
		// ffff:ffff:ffff:ffff = pow(40, 1)
		var ip_count_to_breach_subnet = int(math.Pow(float64(o.BlockIpv6SubnetsBreach), float64(o.BlockIpv6SubnetsGroupDepth - len(strings.Split(o.Ipv6Subnets[i].Group, ":")) + 1)))

		if (o.Ipv6Subnets[i].IpBans >= ip_count_to_breach_subnet) {

			// this subnet group has breached the limit
			// block it
			ipv6_modify_subnet_block_os(o, false, o.Ipv6Subnets[i].Group)
			o.Ipv6Subnets[i].BlockedTs = int(time.Now().Unix())

			// increment the blocked subnet count
			cblocked_subnet += 1

			if (o.NotifyClosure != nil) {

				// send notification
				go o.NotifyClosure("IPv6 Subnet Blocked", []string{o.Ipv6Subnets[i].Group})

			}

		}

	}

	// update the ipac blocked subnet count
	o.BlockedSubnetCount = cblocked_subnet

	if (o.NotifyClosure != nil) {

		if (len(o.NextNotifyBlockedIps) > 0) {

			// send notification
			go o.NotifyClosure("IP addresses blocked.", o.NextNotifyBlockedIps)

			// empty slice
			o.NextNotifyBlockedIps = nil

		}

		if (len(o.NextNotifyAbsurdIps) > 0 && o.LastNotifyAbsurd > int(time.Now().Unix()) - o.BlockForSeconds) {

			// send notification
			go o.NotifyClosure("Too many failed login attempts from IP Addresses that are already authenticated.", o.NextNotifyAbsurdIps)

			// empty slice
			o.NextNotifyAbsurdIps = nil

			// set last notify absurd timestamp
			o.LastNotifyAbsurd = int(time.Now().Unix())

		}

	}

	ipac_mutex.Unlock()

	go clean(o)

}

func ipv6_get_ranked_groups(o *Ipac, addr string) ([]string) {

	// get each ranked group after o.BlockIpv6SubnetsGroupDepth
	// if addr is ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	// and o.BlockIpv6SubnetsGroupDepth is 4
	// return
	// ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff:ffff
	// ffff:ffff:ffff:ffff:ffff:ffff:ffff
	// to match by these prefixes as ipv6 subnets quickly

	var groups = strings.Split(addr, ":")

	var ranked_groups []string

	var at = 0

	for g := 0; g < o.BlockIpv6SubnetsGroupDepth; g++ {

		var prefix = ""

		// add first to `o.BlockIpv6SubnetsGroupDepth` strings of `groups`
		for l := 0; l < o.BlockIpv6SubnetsGroupDepth; l++ {
			prefix += groups[l] + ":"
		}

		// remove the last :
		prefix = strings.TrimRight(prefix, ":")

		// then `o.BlockIpv6SubnetsGroupDepth` to `o.BlockIpv6SubnetsGroupDepth+at` strings of `groups`
		for l := 0; l < at; l++ {
			prefix += groups[l + o.BlockIpv6SubnetsGroupDepth] + ":"
		}

		// remove the last :
		prefix = strings.TrimRight(prefix, ":")

		// add to ranked_groups
		ranked_groups = append(ranked_groups, prefix)

		// increment `at`
		at += 1

	}

	return ranked_groups

}

func ipv6_modify_subnet_block_os(o *Ipac, block bool, subnet string) {

	// block or unblock the subnet at the OS level

	// make 'ffff' or 'ffff:ffff' be a full ipv6 subnet specified with zeros instead of CIDR
	// ffff:0000:0000:0000:0000:0000:0000:0000
	// ffff:ffff:0000:0000:0000:0000:0000:0000
	var groups = strings.Split(subnet, ":")

	var total = 8
	var c = 0
	var iptables_subnet_string = ""
	for (c < total) {

		if (len(groups) <= c + 1) {
			iptables_subnet_string += "0000:"
		} else {
			iptables_subnet_string += groups[c] + ":"
		}

		c += 1

	}

	// remove the last :
	iptables_subnet_string = strings.TrimRight(iptables_subnet_string, ":")

	if (block == true) {

		// block the ip address
		if (runtime.GOOS == "linux") {
			comm(o, "sudo iptables -I goipac -s " + iptables_subnet_string + " -j DROP")
		}

	} else {

		// unblock the ip address
		if (runtime.GOOS == "linux") {
			comm(o, "sudo iptables -D goipac -s " + iptables_subnet_string + " -j DROP")
		}

	}

}

func modify_ip_block_os(o *Ipac, block bool, i Ip) {

	// block or unblock the ip at the OS level

	if (block == true) {

		// block the ip address
		if (runtime.GOOS == "linux") {
			comm(o, "sudo iptables -I goipac -s " + i.Addr + " -j DROP")
		}

	} else {

		// unblock the ip address
		if (runtime.GOOS == "linux") {
			comm(o, "sudo iptables -D goipac -s " + i.Addr + " -j DROP")
		}

	}

}

func IpDetails(o *Ipac, addr string) (Ip) {

	var i Ip

	ipac_mutex.Lock()

	for l := range o.Ips {
		if (o.Ips[l].Addr == addr) {
			i = o.Ips[l]
			break
		}
	}

	ipac_mutex.Unlock()

	return i

}

func TestIpWarn(o *Ipac, addr string) (bool) {

	return IpDetails(o, addr).Warn

}

func TestIpAllowed(o *Ipac, addr string) (bool) {

	// always ran at the start of any request
	// returns false if the IP address has made too many unauthenticated requests and is not allowed
	// returns true if the connection is allowed

	if (o.NeverBlock == true) {
		return true
	}

	// get the ip entry
	var entry = IpDetails(o, addr)

	if (o.Purge == true) {
		// do not allow modification while purging
		if (entry.Blocked == true) {
			return false
		} else {
			return true
		}
	}

	ipac_mutex.Lock()

	// set the last access time of the ip
	entry.LastAccess = int(time.Now().Unix())

	if (entry.Addr == addr) {

		// a matching ip address has been found

		if (entry.Authed == false) {
			// increment the number of unauthed connections from this ip
			entry.UnauthedNewConnections += 1
		}

		// warn this ip address if required
		if (entry.UnauthedNewConnections >= o.WarnAfterNewConnections && entry.Warn == false) {
			// made too many unauthed connections
			entry.Warn = true
		} else if (entry.UnauthedAttempts >= o.WarnAfterUnauthedAttempts && entry.Warn == false) {
			// made too many unauthed attempts
			entry.Warn = true
		}

		// block this ip address if it has made too many unauthed connections
		// or invalid authorization attempts
		if ((entry.UnauthedNewConnections >= o.BlockAfterNewConnections || entry.UnauthedAttempts >= o.BlockAfterUnauthedAttempts) && entry.Blocked == false) {

			// set the ip address to be blocked
			entry.Blocked = true

			// block this ip at the OS level
			modify_ip_block_os(o, true, entry)

			if (o.NotifyClosure != nil) {

				// add to next notify block ips
				o.NextNotifyBlockedIps = append(o.NextNotifyBlockedIps, entry.Addr)

			}

			if (strings.Index(addr, ":") != -1) {
				// this is an IPv6 address

				var ranked_groups = ipv6_get_ranked_groups(o, addr)

				// add the ranked groups to the subnet classifications
				for a := 0; a < len(ranked_groups); a++ {

					var found = false
					for l := range o.Ipv6Subnets {
						if (ranked_groups[l] == o.Ipv6Subnets[l].Group) {
							// already exists
							found = true
							// increment IpBans
							o.Ipv6Subnets[l].IpBans += 1
							break
						}
					}

					if (found == false) {
						// add new
						o.Ipv6Subnets = append(o.Ipv6Subnets, Ipv6Subnet{Group: ranked_groups[a], IpBans: 1})
					}

				}

			}

		} else if (entry.AbsurdAuthAttempts == o.NotifyAfterAbsurdAuthAttempts) {

			// too many auth attempts while the IP has an authenticated session

			if (o.NotifyClosure != nil) {

				// add unique to next notify absurd ips
				var already_absurd = false
				for i := range o.NextNotifyAbsurdIps {
					if (o.NextNotifyAbsurdIps[i] == entry.Addr) {
						// ip address is already in list
						already_absurd = true
						break
					}
				}
				if (already_absurd == false) {
					o.NextNotifyAbsurdIps = append(o.NextNotifyAbsurdIps, entry.Addr)
				}

			}

		}

		// update the o.Ips table
		for l := range o.Ips {
			if (o.Ips[l].Addr == addr) {
				o.Ips[l] = entry
				break
			}
		}

	} else {

		// this ip address is new
		entry.Addr = addr
		o.Ips = append(o.Ips, entry)
		//fmt.Println("ipac.TestIpAllowed, new ip added", len(o.Ips), entry)

	}

	ipac_mutex.Unlock()

	if (entry.Blocked == true) {
		return false
	} else {
		return true
	}

}

func Purge(o *Ipac) {
	// clear all ips
	ipac_mutex.Lock()
	o.Purge = true

	if (runtime.GOOS == "linux") {
		// flush the goipac chain
		comm(o, "sudo iptables -F goipac")
	}

	ipac_mutex.Unlock()
}

func ModifyAuth(o *Ipac, authed int, addr string) {

	if (o.Purge == true) {
		// do not allow modification while purging
		return
	}

	if (o.NeverBlock == true) {
		return
	}

	// get the ip entry
	var entry = IpDetails(o, addr)

	ipac_mutex.Lock()

	var now = int(time.Now().Unix())

	if (entry.Authed == true && authed == 1) {

		// an IP address is authorized but invalid authorizations are happening from the IP
		// perhaps someone else at the location is abusing the authed IP address and trying to guess
		// logins or logout the valid user
		// as node-ip-ac will not deauth an IP without specific instruction to do so
		//
		// modify_auth() should be passed undefined as the authed argument when there is a valid logout
		//
		// increment absurd_auth_attempts
		// to notify the admin and allow the valid user to continue normally

		entry.AbsurdAuthAttempts += 1

	} else if (now - entry.LastAccess > o.BlockForSeconds || authed == 2) {

		// authorized or expired

		// reset the object keys
		// removes the requirement for waiting until the next cleanup iteration

		entry.Blocked = false
		entry.Warn = false

		if (authed == 2) {
			// authorized
			entry.Authed = true
		} else {
			// expired
			// only reset these counters when ModifyAuth is resetting an expired IP address
			entry.AbsurdAuthAttempts = 0
			entry.UnauthedAttempts = 0
			entry.UnauthedNewConnections = 0
		}

	} else if (authed == 1) {

		// not authorized, not expired

		// increment the invalid authorization attempts counter for this IP address
		entry.UnauthedAttempts += 1

	} else if (authed == 0) {

		// valid logout
		entry.Authed = false

	}

	// set the last auth time of the ip
	entry.LastAuth = now

	// update the o.Ips table
	for l := range o.Ips {
		if (o.Ips[l].Addr == addr) {
			o.Ips[l] = entry
			break
		}
	}

	ipac_mutex.Unlock()

	return

}
