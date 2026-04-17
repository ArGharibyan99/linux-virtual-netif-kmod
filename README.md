# linux-virtual-netif-kmod

A Linux kernel module that creates virtual network interfaces (`vnet0`, `vnet1`, ...) controlled via procfs. Each interface handles ARP requests and ICMP echo requests in the kernel, replying without a real network device.

## Features

- Creates a `vnet0` interface on load
- Add and delete interfaces at runtime via procfs
- Assign IPv4 addresses via procfs
- Responds to ARP requests and ICMP echo (ping) locally
- Works as a bridge slave — supports remote ping through a bridge topology

## Requirements

- Linux kernel headers for the running kernel (`linux-headers-$(uname -r)`)
- `gcc`, `make`
- `cmake` >= 3.14 (for tests)
- `iproute2`, `bridge-utils` (for manual testing and remote ping tests)
- Root privileges for loading the module and running tests

## Project Structure

```
.
├── src/
│   └── vnetif.c        # Kernel module source
├── tests/
│   ├── CMakeLists.txt  # CMake build for GTest integration tests
│   └── vnetif_test.cc  # Integration tests
└── Makefile
```

## Build

```bash
make
```

Builds the kernel module to `build/vnetif.ko`.

```bash
make clean
```

Removes the entire `build/` directory.

## Test

```bash
make test
```

Builds the module, compiles the GTest integration tests (downloading GoogleTest automatically), and runs the full test suite as root. The suite covers:

- Interface creation on module load
- Adding and deleting interfaces via procfs
- IPv4 address assignment on multiple interfaces
- Local self-ping on `vnet0` and additional interfaces
- Remote ping through a bridge + network namespace topology

## Procfs Interface

| Entry | Permission | Description |
|---|---|---|
| `/proc/vnetif` | read | List all interfaces and their IPv4 addresses |
| `/proc/vnetif_add` | write | Create a new interface |
| `/proc/vnetif_del` | write | Delete an interface by name |
| `/proc/vnetif_ipv4` | write | Assign an IPv4 address to an interface |

## Manual Commands

### Load and unload

```bash
# Load the module
sudo insmod build/vnetif.ko

# Unload the module (removes all vnet interfaces)
sudo rmmod vnetif
```

### Interface management

```bash
# List interfaces and their IPs
cat /proc/vnetif

# Add a new interface (creates vnet1, vnet2, ...)
echo 1 | sudo tee /proc/vnetif_add

# Delete an interface
echo 'vnet1' | sudo tee /proc/vnetif_del

# Assign an IPv4 address
echo 'vnet0 10.10.10.1' | sudo tee /proc/vnetif_ipv4
```

### Local ping

```bash
sudo insmod build/vnetif.ko
sudo nmcli device set vnet0 managed no
echo 'vnet0 10.10.10.1' | sudo tee /proc/vnetif_ipv4
ping -I vnet0 10.10.10.1 -c 3
sudo rmmod vnetif
```

### Remote ping via bridge and network namespace

```bash
sudo insmod build/vnetif.ko
sudo nmcli device set vnet0 managed no
echo 'vnet0 10.10.10.1' | sudo tee /proc/vnetif_ipv4

# Create bridge
sudo ip link add br-test type bridge
sudo ip link set br-test address 00:00:00:00:00:01
sudo ip link set br-test up

# Create veth pair
sudo ip link add veth-host type veth peer name veth-ns
sudo ip link set veth-host master br-test
sudo ip link set veth-host up

# Attach vnet0 to bridge
sudo ip link set vnet0 master br-test
sudo ip link set vnet0 up

# Remove the bridge LOCAL FDB entry for vnet0 so the bridge forwards
# frames destined for vnet0's MAC to its xmit handler
VNET0_MAC=$(ip link show dev vnet0 | awk '/link\/ether/{print $2}')
sudo bridge fdb del "$VNET0_MAC" dev vnet0 master

# Create network namespace with veth-ns
sudo ip netns add ns1
sudo ip link set veth-ns netns ns1
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns1 ip link set veth-ns up
sudo ip netns exec ns1 ip addr add 10.10.10.2/24 dev veth-ns

# Ping vnet0 from the namespace
sudo ip netns exec ns1 ping 10.10.10.1 -c 3

# Cleanup
sudo ip netns del ns1
sudo ip link del veth-host
sudo ip link del br-test
sudo rmmod vnetif
```

## License

GPL — see [LICENSE](LICENSE).
