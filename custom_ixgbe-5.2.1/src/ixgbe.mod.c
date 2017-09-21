#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x96cec1da, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x95344561, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0x2d3385d3, __VMLINUX_SYMBOL_STR(system_wq) },
	{ 0x9c2c0762, __VMLINUX_SYMBOL_STR(device_remove_file) },
	{ 0x67a9c574, __VMLINUX_SYMBOL_STR(netdev_info) },
	{ 0x643c4c76, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xf6d780b0, __VMLINUX_SYMBOL_STR(pci_bus_read_config_byte) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x1d11b5d6, __VMLINUX_SYMBOL_STR(ethtool_op_get_ts_info) },
	{ 0xe4689576, __VMLINUX_SYMBOL_STR(ktime_get_with_offset) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x99840d00, __VMLINUX_SYMBOL_STR(timecounter_init) },
	{ 0x244916f, __VMLINUX_SYMBOL_STR(dcb_ieee_setapp) },
	{ 0x8144c064, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0x619cb7dd, __VMLINUX_SYMBOL_STR(simple_read_from_buffer) },
	{ 0xfdc45d4e, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0xedf578ce, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0xafc288c0, __VMLINUX_SYMBOL_STR(dcb_ieee_delapp) },
	{ 0x3c8ce86, __VMLINUX_SYMBOL_STR(napi_disable) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x29ad3899, __VMLINUX_SYMBOL_STR(pci_sriov_set_totalvfs) },
	{ 0xcb80e06a, __VMLINUX_SYMBOL_STR(__napi_schedule_irqoff) },
	{ 0xada2baa5, __VMLINUX_SYMBOL_STR(skb_pad) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x9469482, __VMLINUX_SYMBOL_STR(kfree_call_rcu) },
	{ 0xd0b8e59a, __VMLINUX_SYMBOL_STR(napi_gro_flush) },
	{ 0xbd100793, __VMLINUX_SYMBOL_STR(cpu_online_mask) },
	{ 0x3a9b5f2d, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0xbfabd074, __VMLINUX_SYMBOL_STR(napi_hash_del) },
	{ 0x3637f396, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0x7043a19c, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x2ff9eb8b, __VMLINUX_SYMBOL_STR(hwmon_device_unregister) },
	{ 0x4ea25709, __VMLINUX_SYMBOL_STR(dql_reset) },
	{ 0x3f7b2feb, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0xd9d3bcd3, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0xe770be2a, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0x9751bbf3, __VMLINUX_SYMBOL_STR(__hw_addr_sync_dev) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0xc121d96f, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0x88bfa7e, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0x4fa7d0c6, __VMLINUX_SYMBOL_STR(pci_dev_get) },
	{ 0x3fec048f, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0x949f7342, __VMLINUX_SYMBOL_STR(__alloc_percpu) },
	{ 0x116f95f, __VMLINUX_SYMBOL_STR(driver_for_each_device) },
	{ 0xc0d794b8, __VMLINUX_SYMBOL_STR(__dev_kfree_skb_any) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x9580deb, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0x5df040aa, __VMLINUX_SYMBOL_STR(dma_free_attrs) },
	{ 0xe02a1009, __VMLINUX_SYMBOL_STR(pci_bus_write_config_word) },
	{ 0x4218e085, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0xb5aa7165, __VMLINUX_SYMBOL_STR(dma_pool_destroy) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0xe6071ab6, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0xf4c91ed, __VMLINUX_SYMBOL_STR(ns_to_timespec) },
	{ 0x6438e178, __VMLINUX_SYMBOL_STR(pci_dev_driver) },
	{ 0x8bbc1a6d, __VMLINUX_SYMBOL_STR(netif_napi_del) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xc9ec4e21, __VMLINUX_SYMBOL_STR(free_percpu) },
	{ 0x290d0055, __VMLINUX_SYMBOL_STR(__dynamic_netdev_dbg) },
	{ 0x733c3b54, __VMLINUX_SYMBOL_STR(kasprintf) },
	{ 0x27c33efe, __VMLINUX_SYMBOL_STR(csum_ipv6_magic) },
	{ 0xba7e1125, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0x79c90186, __VMLINUX_SYMBOL_STR(ptp_clock_unregister) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0x90ded659, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x57665d80, __VMLINUX_SYMBOL_STR(dca3_get_tag) },
	{ 0xdf2f9fc8, __VMLINUX_SYMBOL_STR(netif_schedule_queue) },
	{ 0x6fbc3d06, __VMLINUX_SYMBOL_STR(ptp_clock_event) },
	{ 0x706d051c, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xfd98e814, __VMLINUX_SYMBOL_STR(dcb_getapp) },
	{ 0x884dc06d, __VMLINUX_SYMBOL_STR(dcb_setapp) },
	{ 0x420c814, __VMLINUX_SYMBOL_STR(pci_enable_pcie_error_reporting) },
	{ 0xac34ecec, __VMLINUX_SYMBOL_STR(dca_register_notify) },
	{ 0xed663b1d, __VMLINUX_SYMBOL_STR(netif_tx_wake_queue) },
	{ 0x5066d1cb, __VMLINUX_SYMBOL_STR(pci_restore_state) },
	{ 0x301fb7ee, __VMLINUX_SYMBOL_STR(netif_tx_stop_all_queues) },
	{ 0x1a33ab9, __VMLINUX_SYMBOL_STR(dca_unregister_notify) },
	{ 0xf7c2cca1, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x1916e38c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x7d0a7181, __VMLINUX_SYMBOL_STR(dev_addr_del) },
	{ 0x4e71f3e7, __VMLINUX_SYMBOL_STR(netif_set_xps_queue) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x1a8aa5cd, __VMLINUX_SYMBOL_STR(ethtool_op_get_link) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x3c3fce39, __VMLINUX_SYMBOL_STR(__local_bh_enable_ip) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xa00aca2a, __VMLINUX_SYMBOL_STR(dql_completed) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xcd279169, __VMLINUX_SYMBOL_STR(nla_find) },
	{ 0x88c32da3, __VMLINUX_SYMBOL_STR(vxlan_get_rx_port) },
	{ 0x128cf3fb, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x1a09356e, __VMLINUX_SYMBOL_STR(register_netdev) },
	{ 0x65907f2b, __VMLINUX_SYMBOL_STR(dma_alloc_attrs) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0xa90260e7, __VMLINUX_SYMBOL_STR(dev_close) },
	{ 0xc52120c1, __VMLINUX_SYMBOL_STR(netif_set_real_num_rx_queues) },
	{ 0x16e5c2a, __VMLINUX_SYMBOL_STR(mod_timer) },
	{ 0x91513898, __VMLINUX_SYMBOL_STR(netif_set_real_num_tx_queues) },
	{ 0x34285aad, __VMLINUX_SYMBOL_STR(netif_napi_add) },
	{ 0x2a37d074, __VMLINUX_SYMBOL_STR(dma_pool_free) },
	{ 0x155525ad, __VMLINUX_SYMBOL_STR(dcb_ieee_getapp_mask) },
	{ 0xd9536300, __VMLINUX_SYMBOL_STR(ptp_clock_register) },
	{ 0x2072ee9b, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0xf73842f6, __VMLINUX_SYMBOL_STR(dca_add_requester) },
	{ 0xee1f6daf, __VMLINUX_SYMBOL_STR(simple_open) },
	{ 0x35ffcbfb, __VMLINUX_SYMBOL_STR(__get_page_tail) },
	{ 0x9f46ced8, __VMLINUX_SYMBOL_STR(__sw_hweight64) },
	{ 0x22c519cd, __VMLINUX_SYMBOL_STR(dev_open) },
	{ 0xe523ad75, __VMLINUX_SYMBOL_STR(synchronize_irq) },
	{ 0xc542933a, __VMLINUX_SYMBOL_STR(timecounter_read) },
	{ 0x65ff8006, __VMLINUX_SYMBOL_STR(pci_find_capability) },
	{ 0xc842789a, __VMLINUX_SYMBOL_STR(device_create_file) },
	{ 0xc911b9d5, __VMLINUX_SYMBOL_STR(eth_get_headlen) },
	{ 0xd97c8829, __VMLINUX_SYMBOL_STR(pci_select_bars) },
	{ 0xc067a67d, __VMLINUX_SYMBOL_STR(netif_receive_skb_sk) },
	{ 0xa8b76a68, __VMLINUX_SYMBOL_STR(timecounter_cyc2time) },
	{ 0x696a2e97, __VMLINUX_SYMBOL_STR(netif_device_attach) },
	{ 0x86971b75, __VMLINUX_SYMBOL_STR(napi_gro_receive) },
	{ 0xc9778cba, __VMLINUX_SYMBOL_STR(__hw_addr_unsync_dev) },
	{ 0xe67759ca, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0x40a9b349, __VMLINUX_SYMBOL_STR(vzalloc) },
	{ 0x629a09c5, __VMLINUX_SYMBOL_STR(dev_addr_add) },
	{ 0xce17ea11, __VMLINUX_SYMBOL_STR(__free_pages) },
	{ 0x2f88f68c, __VMLINUX_SYMBOL_STR(pci_disable_link_state) },
	{ 0x618911fc, __VMLINUX_SYMBOL_STR(numa_node) },
	{ 0xa3190184, __VMLINUX_SYMBOL_STR(netif_device_detach) },
	{ 0x461e6c85, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0x12a38747, __VMLINUX_SYMBOL_STR(usleep_range) },
	{ 0xecffc9a6, __VMLINUX_SYMBOL_STR(pci_enable_msix_range) },
	{ 0x8d36dd74, __VMLINUX_SYMBOL_STR(pci_bus_read_config_word) },
	{ 0xfa0e38de, __VMLINUX_SYMBOL_STR(ipv6_skip_exthdr) },
	{ 0xed00471a, __VMLINUX_SYMBOL_STR(pci_bus_read_config_dword) },
	{ 0xbba70a2d, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0x596db8a9, __VMLINUX_SYMBOL_STR(pci_cleanup_aer_uncorrect_error_status) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb9249d16, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0xf868aae, __VMLINUX_SYMBOL_STR(skb_checksum_help) },
	{ 0xc936e567, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x23cedc9f, __VMLINUX_SYMBOL_STR(napi_hash_add) },
	{ 0xf374f349, __VMLINUX_SYMBOL_STR(ndo_dflt_fdb_add) },
	{ 0xaea9eb40, __VMLINUX_SYMBOL_STR(napi_complete_done) },
	{ 0xb0db5ee4, __VMLINUX_SYMBOL_STR(eth_type_trans) },
	{ 0x771cf835, __VMLINUX_SYMBOL_STR(dma_pool_alloc) },
	{ 0x4285f63c, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xe8700006, __VMLINUX_SYMBOL_STR(netdev_err) },
	{ 0xa0431f70, __VMLINUX_SYMBOL_STR(netdev_features_change) },
	{ 0x467df16d, __VMLINUX_SYMBOL_STR(netdev_rss_key_fill) },
	{ 0xcf6bc653, __VMLINUX_SYMBOL_STR(pci_enable_msi_range) },
	{ 0xa997e3f1, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0xcc5005fe, __VMLINUX_SYMBOL_STR(msleep_interruptible) },
	{ 0xa4d5abf7, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x3928efe9, __VMLINUX_SYMBOL_STR(__per_cpu_offset) },
	{ 0x680ec266, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xf6ebc03b, __VMLINUX_SYMBOL_STR(net_ratelimit) },
	{ 0x4dbdf8b7, __VMLINUX_SYMBOL_STR(pci_set_power_state) },
	{ 0x521a8e68, __VMLINUX_SYMBOL_STR(netdev_warn) },
	{ 0xbb4f4766, __VMLINUX_SYMBOL_STR(simple_write_to_buffer) },
	{ 0xf1ff51a4, __VMLINUX_SYMBOL_STR(eth_validate_addr) },
	{ 0x9da21a6a, __VMLINUX_SYMBOL_STR(pci_disable_pcie_error_reporting) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x87e27496, __VMLINUX_SYMBOL_STR(___pskb_trim) },
	{ 0x5f85d1e, __VMLINUX_SYMBOL_STR(param_array_ops) },
	{ 0x9d76eeab, __VMLINUX_SYMBOL_STR(ptp_clock_index) },
	{ 0x38d321c0, __VMLINUX_SYMBOL_STR(pci_disable_msi) },
	{ 0x6f820778, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x73964657, __VMLINUX_SYMBOL_STR(skb_add_rx_frag) },
	{ 0xca48eb66, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0xe98057d8, __VMLINUX_SYMBOL_STR(pci_prepare_to_sleep) },
	{ 0x13b81555, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xa8721b97, __VMLINUX_SYMBOL_STR(system_state) },
	{ 0xbb5866a4, __VMLINUX_SYMBOL_STR(pci_get_device) },
	{ 0x63c4d61f, __VMLINUX_SYMBOL_STR(__bitmap_weight) },
	{ 0xa75d4ff0, __VMLINUX_SYMBOL_STR(dev_warn) },
	{ 0xe480aa2, __VMLINUX_SYMBOL_STR(unregister_netdev) },
	{ 0xf2938ff8, __VMLINUX_SYMBOL_STR(ndo_dflt_bridge_getlink) },
	{ 0x55f5019b, __VMLINUX_SYMBOL_STR(__kmalloc_node) },
	{ 0x3a3d836e, __VMLINUX_SYMBOL_STR(pci_dev_put) },
	{ 0x84eb952, __VMLINUX_SYMBOL_STR(netif_wake_subqueue) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0xad05c250, __VMLINUX_SYMBOL_STR(pci_vfs_assigned) },
	{ 0x9e0c711d, __VMLINUX_SYMBOL_STR(vzalloc_node) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x26565c5f, __VMLINUX_SYMBOL_STR(consume_skb) },
	{ 0xb884b79e, __VMLINUX_SYMBOL_STR(dca_remove_requester) },
	{ 0x2223b02f, __VMLINUX_SYMBOL_STR(pci_enable_device_mem) },
	{ 0x379825f8, __VMLINUX_SYMBOL_STR(__napi_alloc_skb) },
	{ 0xa02e9893, __VMLINUX_SYMBOL_STR(skb_tstamp_tx) },
	{ 0xc4d0ec1e, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xbba72e14, __VMLINUX_SYMBOL_STR(pci_wake_from_d3) },
	{ 0xf0a71e70, __VMLINUX_SYMBOL_STR(pci_release_selected_regions) },
	{ 0xf86ab063, __VMLINUX_SYMBOL_STR(pci_request_selected_regions) },
	{ 0xbb128381, __VMLINUX_SYMBOL_STR(irq_set_affinity_hint) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x9c32a50a, __VMLINUX_SYMBOL_STR(dma_pool_create) },
	{ 0x8e29cbff, __VMLINUX_SYMBOL_STR(skb_copy_bits) },
	{ 0xcc20434a, __VMLINUX_SYMBOL_STR(hwmon_device_register) },
	{ 0x239d44c8, __VMLINUX_SYMBOL_STR(pci_find_ext_capability) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0x9e7d6bd0, __VMLINUX_SYMBOL_STR(__udelay) },
	{ 0x6ce2322d, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x59093418, __VMLINUX_SYMBOL_STR(pcie_get_minimum_link) },
	{ 0xcc7b61e7, __VMLINUX_SYMBOL_STR(pcie_capability_read_word) },
	{ 0xcf24240a, __VMLINUX_SYMBOL_STR(device_set_wakeup_enable) },
	{ 0xf20dabd8, __VMLINUX_SYMBOL_STR(free_irq) },
	{ 0xaf2ef0f9, __VMLINUX_SYMBOL_STR(pci_save_state) },
	{ 0x3767c91f, __VMLINUX_SYMBOL_STR(alloc_etherdev_mqs) },
	{ 0x31a8476, __VMLINUX_SYMBOL_STR(netdev_crit) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ptp,dca,vxlan";

MODULE_ALIAS("pci:v00008086d000010B6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Bsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DDsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010ECsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001508sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010FCsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001517sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010FBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001507sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001514sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000152Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001529sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000151Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001528sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001557sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001558sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001560sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001563sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015D1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015AAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015B0sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ABsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ACsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ADsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015AEsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C2sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C3sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015C8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015CAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015CCsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015CEsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015E4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015E5sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "4DCEFE96581F547E735C8B6");
