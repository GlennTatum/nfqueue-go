// Implementation of https://git.netfilter.org/libmnl/tree/examples/netfilter/nf-queue.c using cgo

/*
This is still a work in progress

User Documentation:

Create a netfilter queue to forward packets to queue number 1. Currently there is no verdict logic, so bypass
should be set to run in a 'passive' inspection mode to prevent packets from hanging without a verdict being applied.

```
sudo nft add table inet icmp_filter

sudo nft 'add chain inet icmp_filter input { type filter hook input priority 0; policy accept; }'

sudo nft add rule inet icmp_filter input ip protocol icmp counter queue num 1 bypass
```

*/

package main

/*
#cgo LDFLAGS: -lmnl -lnetfilter_queue

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

// make an equivlant typedef to export. See:  https://www.netfilter.org/projects/libmnl/doxygen/html/socket_8c_source.html
typedef struct mnl_socket {
        int                     fd;
        struct sockaddr_nl      addr;
} mnl_socket;

*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"syscall"
	"unsafe"
)

const (
	MNL_SOCKET_BUFFER_SIZE = 4096
	BUF_MIN_SIZE           = 65535
)

func main() {

	runtime.MemProfileRate = 1 // track each heap allocation, not 512kb chunks periodically

	runtime.GC()
	memProfile, err := os.Create("example-mem.prof")
	if err != nil {
		log.Fatal(err)
	}
	defer memProfile.Close()
	if err := pprof.WriteHeapProfile(memProfile); err != nil {
		log.Fatal(err)
	}

	if err := setup(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// Source: https://www.netfilter.org/projects/libmnl/doxygen/html/socket_8c_source.html
func mnl_socket_recv(counter *int, nl *C.mnl_socket, buf []byte) error {
	oob := make([]byte, BUF_MIN_SIZE+(MNL_SOCKET_BUFFER_SIZE/2)) // TODO Check oob overflow

	n, oobn, _, _, err := syscall.Recvmsg(int(nl.fd), buf, oob, 0)
	if err != nil {
		return err
	}
	// TODO decode packet structure written to buf based on protocol types.
	*counter++
	fmt.Printf("Packet Recieved: %d | n: %d | oobn: %d\n", *counter, n, oobn)
	fmt.Print(hex.Dump(buf[:n]))
	return nil
}

func netfilter_queue_connect(queue_num int) (*C.mnl_socket, error) {
	queue_num_c := (C.uint32_t)(queue_num)
	nl := C.mnl_socket_open(C.NETLINK_NETFILTER)
	if nl == nil {
		return nil, fmt.Errorf("mnl_socket_open")
	}
	if C.mnl_socket_bind(nl, 0, C.MNL_SOCKET_AUTOPID) < 0 {
		return nil, fmt.Errorf("mnl_socket_bind")
	}

	initmsg := make([]C.char, BUF_MIN_SIZE+(MNL_SOCKET_BUFFER_SIZE/2))

	// nlh is the netlink initial packet send to the subsystem to configure the queue
	nlh := C.nfq_nlmsg_put(&initmsg[0], C.NFQNL_MSG_CONFIG, queue_num_c)
	C.nfq_nlmsg_cfg_put_cmd(nlh, C.AF_INET, C.NFQNL_CFG_CMD_BIND)

	if C.mnl_socket_sendto(nl, unsafe.Pointer(nlh), (C.size_t)(nlh.nlmsg_len)) < 0 {
		return nil, fmt.Errorf("mnl_socket_send")
	}

	nlh = C.nfq_nlmsg_put(&initmsg[0], C.NFQNL_MSG_CONFIG, queue_num_c)
	C.nfq_nlmsg_cfg_put_cmd(nlh, C.AF_INET, C.NFQNL_CFG_CMD_BIND)
	if C.mnl_socket_sendto(nl, unsafe.Pointer(nlh), C.size_t(nlh.nlmsg_len)) < 0 {
		return nil, fmt.Errorf("mnl_socket_send")
	}

	nlh = C.nfq_nlmsg_put(&initmsg[0], C.NFQNL_MSG_CONFIG, queue_num_c)
	C.nfq_nlmsg_cfg_put_params(nlh, C.NFQNL_COPY_PACKET, 0xffff)

	C.mnl_attr_put_u32(nlh, C.NFQA_CFG_FLAGS, C.htonl(C.NFQA_CFG_F_GSO))
	C.mnl_attr_put_u32(nlh, C.NFQA_CFG_MASK, C.htonl(C.NFQA_CFG_F_GSO))

	if C.mnl_socket_sendto(nl, unsafe.Pointer(nlh), C.size_t(nlh.nlmsg_len)) < 0 {
		return nil, fmt.Errorf("mnl_socket_send")
	}

	fmt.Println(nlh)

	buf := make([]byte, BUF_MIN_SIZE+(MNL_SOCKET_BUFFER_SIZE/2))
	counter := 0
	// TODO add cancellation handlers
	for {
		mnl_socket_recv(&counter, nl, buf)
	}

	return (*C.mnl_socket)(nl), nil
}

func setup() error {
	_, err := netfilter_queue_connect(1)
	return err
}
