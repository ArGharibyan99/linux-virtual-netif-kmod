/*
 * Integration tests for the vnetif kernel module.
 *
 * Tests interact with the live kernel module via procfs and standard
 * networking tools (ip, ping, bridge).  The test binary must be run as
 * root (sudo ./vnetif_tests) from the project root directory so that
 * build/vnetif.ko is reachable via the relative path.
 */

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int run(const std::string &cmd)
{
    return system(cmd.c_str());
}

static std::string capture(const std::string &cmd)
{
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        return {};
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe))
        result += buf;
    pclose(pipe);
    return result;
}

static bool iface_exists(const std::string &name)
{
    return run("ip link show dev " + name + " >/dev/null 2>&1") == 0;
}

static bool proc_lists(const std::string &name)
{
    return capture("cat /proc/vnetif").find(name) != std::string::npos;
}

static bool has_ip(const std::string &iface, const std::string &ip_cidr)
{
    return capture("ip -4 addr show dev " + iface).find(ip_cidr) != std::string::npos;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr const char *MOD_NAME   = "vnetif";
static constexpr const char *MOD_PATH   = "build/vnetif.ko";
static constexpr const char *IF0        = "vnet0";
static constexpr const char *IF1        = "vnet1";
static constexpr const char *IF2        = "vnet2";
static constexpr const char *IP0        = "10.10.10.1";
static constexpr const char *IP1        = "10.10.20.1";
static constexpr const char *IP2        = "10.10.30.1";
static constexpr const char *BR_NAME    = "br-test";
static constexpr const char *VETH_HOST  = "veth-host";
static constexpr const char *VETH_NS    = "veth-ns";
static constexpr const char *NS_NAME    = "ns1";
static constexpr const char *NS_IP_CIDR = "10.10.10.2/24";

// ---------------------------------------------------------------------------
// Full cleanup — removes every resource that tests can create.
// Safe to call at any point; all commands suppress errors.
// ---------------------------------------------------------------------------

static void full_cleanup()
{
    run(std::string("ip netns del ")  + NS_NAME   + " 2>/dev/null");
    run(std::string("ip link set ")   + IF0       + " nomaster 2>/dev/null");
    run(std::string("ip link del ")   + VETH_HOST + " 2>/dev/null");
    run(std::string("ip link del ")   + BR_NAME   + " 2>/dev/null");
    // rmmod destroys all vnetN interfaces
    run(std::string("rmmod ")         + MOD_NAME  + " 2>/dev/null");
}

// ---------------------------------------------------------------------------
// Global environment: runs full_cleanup before and after the entire suite.
// Handles dirty state left by a previous crashed or interrupted run.
// ---------------------------------------------------------------------------

class CleanupEnvironment : public ::testing::Environment {
public:
    void SetUp()    override { full_cleanup(); }
    void TearDown() override { full_cleanup(); }
};

// ---------------------------------------------------------------------------
// Module / interface helpers
// ---------------------------------------------------------------------------

static void load_module()
{
    run(std::string("rmmod ") + MOD_NAME + " 2>/dev/null");
    ASSERT_EQ(0, run(std::string("insmod ") + MOD_PATH))
        << "insmod failed – run tests from project root as root";
    run(std::string("nmcli device set ") + IF0 + " managed no 2>/dev/null");
}

static void add_iface(const std::string &expected_name)
{
    ASSERT_EQ(0, run("echo 1 > /proc/vnetif_add"))
        << "write to /proc/vnetif_add failed";
    run("nmcli device set " + expected_name + " managed no 2>/dev/null");
}

static void del_iface(const std::string &name)
{
    ASSERT_EQ(0, run("echo '" + name + "' > /proc/vnetif_del"))
        << "write to /proc/vnetif_del failed for " + name;
}

static void set_ip(const std::string &iface, const std::string &ip)
{
    ASSERT_EQ(0, run("echo '" + iface + " " + ip + "' > /proc/vnetif_ipv4"))
        << "write to /proc/vnetif_ipv4 failed for " + iface;
    usleep(300'000);
}

// ---------------------------------------------------------------------------
// Interface management tests
// ---------------------------------------------------------------------------

class IfaceTest : public ::testing::Test {
protected:
    void SetUp()    override { full_cleanup(); load_module(); }
    void TearDown() override { full_cleanup(); }
};

TEST_F(IfaceTest, DefaultInterfaceCreatedOnLoad)
{
    EXPECT_TRUE(iface_exists(IF0));
    EXPECT_TRUE(proc_lists(IF0));
}

TEST_F(IfaceTest, AddInterface)
{
    add_iface(IF1);
    EXPECT_TRUE(iface_exists(IF1));
    EXPECT_TRUE(proc_lists(IF1));
}

TEST_F(IfaceTest, AddMultipleInterfaces)
{
    add_iface(IF1);
    add_iface(IF2);
    EXPECT_TRUE(iface_exists(IF1));
    EXPECT_TRUE(iface_exists(IF2));
    EXPECT_TRUE(proc_lists(IF1));
    EXPECT_TRUE(proc_lists(IF2));
}

TEST_F(IfaceTest, DeleteInterface)
{
    add_iface(IF1);
    del_iface(IF1);
    EXPECT_FALSE(iface_exists(IF1));
    EXPECT_FALSE(proc_lists(IF1));
}

TEST_F(IfaceTest, DeleteInterfacePreservesOthers)
{
    add_iface(IF1);
    add_iface(IF2);
    del_iface(IF1);

    EXPECT_TRUE(iface_exists(IF0));
    EXPECT_FALSE(iface_exists(IF1));
    EXPECT_TRUE(iface_exists(IF2));
    EXPECT_TRUE(proc_lists(IF0));
    EXPECT_FALSE(proc_lists(IF1));
    EXPECT_TRUE(proc_lists(IF2));
}

TEST_F(IfaceTest, SetIPOnInterface)
{
    set_ip(IF0, IP0);
    EXPECT_TRUE(has_ip(IF0, std::string(IP0) + "/24"));
}

TEST_F(IfaceTest, SetIPOnMultipleInterfaces)
{
    add_iface(IF1);
    add_iface(IF2);

    set_ip(IF0, IP0);
    set_ip(IF1, IP1);
    set_ip(IF2, IP2);

    EXPECT_TRUE(has_ip(IF0, std::string(IP0) + "/24"));
    EXPECT_TRUE(has_ip(IF1, std::string(IP1) + "/24"));
    EXPECT_TRUE(has_ip(IF2, std::string(IP2) + "/24"));
}

TEST_F(IfaceTest, DeleteInterfacePreservesIPsOnOthers)
{
    add_iface(IF1);
    add_iface(IF2);

    set_ip(IF0, IP0);
    set_ip(IF1, IP1);
    set_ip(IF2, IP2);

    del_iface(IF1);

    EXPECT_TRUE(has_ip(IF0, std::string(IP0) + "/24"));
    EXPECT_TRUE(has_ip(IF2, std::string(IP2) + "/24"));
}

TEST_F(IfaceTest, IPAppearsInProcfs)
{
    set_ip(IF0, IP0);
    std::string out = capture("cat /proc/vnetif");
    EXPECT_NE(std::string::npos, out.find(IP0));
}

// ---------------------------------------------------------------------------
// Local ping tests
// ---------------------------------------------------------------------------

class LocalPingTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        full_cleanup();
        load_module();
        set_ip(IF0, IP0);
    }

    void TearDown() override { full_cleanup(); }
};

TEST_F(LocalPingTest, PingSucceeds)
{
    int rc = run(std::string("ping -I ") + IF0 +
                 " " + IP0 + " -c 3 -W 1 -q 2>/dev/null");
    EXPECT_EQ(0, rc) << "local self-ping failed";
}

TEST_F(LocalPingTest, PingSecondInterface)
{
    add_iface(IF1);
    set_ip(IF1, IP1);

    int rc = run(std::string("ping -I ") + IF1 +
                 " " + IP1 + " -c 3 -W 1 -q 2>/dev/null");
    EXPECT_EQ(0, rc) << "local self-ping on " << IF1 << " failed";
}

// ---------------------------------------------------------------------------
// Remote ping tests
// ---------------------------------------------------------------------------

class RemotePingTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        full_cleanup();
        load_module();
        set_ip(IF0, IP0);
        setup_topology();
    }

    void TearDown() override { full_cleanup(); }

private:
    void setup_topology()
    {
        ASSERT_EQ(0, run(std::string("ip link add ") + BR_NAME + " type bridge"));
        ASSERT_EQ(0, run(std::string("ip link set ") + BR_NAME +
                         " address 00:00:00:00:00:01"));
        ASSERT_EQ(0, run(std::string("ip link set ") + BR_NAME + " up"));

        ASSERT_EQ(0, run(std::string("ip link add ") + VETH_HOST +
                         " type veth peer name " + VETH_NS));
        ASSERT_EQ(0, run(std::string("ip link set ") + VETH_HOST +
                         " master " + BR_NAME));
        ASSERT_EQ(0, run(std::string("ip link set ") + VETH_HOST + " up"));

        ASSERT_EQ(0, run(std::string("ip link set ") + IF0 +
                         " master " + BR_NAME));
        ASSERT_EQ(0, run(std::string("ip link set ") + IF0 + " up"));

        // Remove the bridge LOCAL FDB entry for vnet0's MAC so the bridge
        // forwards unicast frames for that MAC to vnet0's xmit handler
        // instead of delivering them locally to the bridge IP stack.
        std::string mac = capture(
            std::string("ip link show dev ") + IF0 +
            " | awk '/link\\/ether/{print $2}'");
        mac.erase(mac.find_last_not_of(" \n\r\t") + 1);
        run("bridge fdb del " + mac + " dev " + std::string(IF0) +
            " master 2>/dev/null");

        ASSERT_EQ(0, run(std::string("ip netns add ") + NS_NAME));
        ASSERT_EQ(0, run(std::string("ip link set ") + VETH_NS +
                         " netns " + NS_NAME));
        ASSERT_EQ(0, run(std::string("ip netns exec ") + NS_NAME +
                         " ip link set lo up"));
        ASSERT_EQ(0, run(std::string("ip netns exec ") + NS_NAME +
                         " ip link set " + VETH_NS + " up"));
        ASSERT_EQ(0, run(std::string("ip netns exec ") + NS_NAME +
                         " ip addr add " + NS_IP_CIDR + " dev " + VETH_NS));
    }
};

TEST_F(RemotePingTest, ARPResolvesNeighbor)
{
    run(std::string("ip netns exec ") + NS_NAME +
        " ip neigh flush all 2>/dev/null");
    run(std::string("ip netns exec ") + NS_NAME +
        " ping " + IP0 + " -c 1 -W 2 -q 2>/dev/null");

    std::string neigh = capture(
        std::string("ip netns exec ") + NS_NAME +
        " ip neigh show " + IP0);
    EXPECT_NE(std::string::npos, neigh.find("lladdr"))
        << "ARP did not resolve: " << neigh;
}

TEST_F(RemotePingTest, PingSucceeds)
{
    run(std::string("ip netns exec ") + NS_NAME +
        " ip neigh flush all 2>/dev/null");
    int rc = run(std::string("ip netns exec ") + NS_NAME +
                 " ping " + IP0 + " -c 3 -W 2 -q 2>/dev/null");
    EXPECT_EQ(0, rc) << "remote ping from " << NS_NAME << " failed";
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new CleanupEnvironment);
    return RUN_ALL_TESTS();
}
