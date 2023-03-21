#ifndef __PLAT_CMN_EFI_H__
#define __PLAT_CMN_EFI_H__

#include <uk/arch/types.h>
#include <uk/arch/limits.h>
#include <uk/essentials.h>
#include <uk/bitcount.h>
#include <stdbool.h>

#if defined(__X86_64__)
#define __uk_efi_api __attribute__((ms_abi))
#else
#define __uk_efi_api
#endif

#define UK_EFI_SUCCESS			0
#define UK_EFI_BUFFER_TOO_SMALL							\
	(5 | (1ULL << ((__SIZEOF_LONG__ << 3) - 1)))

typedef unsigned long uk_efi_status_t;
typedef void *uk_efi_hndl_t;
typedef __u64 uk_efi_uintn_t;
typedef __u64 uk_efi_tpl_t;
typedef void *uk_efi_event_t;
typedef __paddr_t uk_efi_paddr_t;
typedef __vaddr_t uk_efi_vaddr_t;

typedef struct uk_efi_guid {
        __u32 b0_3;
	__u16 b4_5;
	__u16 b6_7;
	__u8 b8_15[8];
} uk_efi_guid_t __align(8);

typedef enum uk_efi_if_type {
	EFI_NATIVE_INTERFACE
} uk_efi_if_type_t;

#define UK_EFI_PAGE_SHIFT		12
#define UK_EFI_PAGE_SIZE		(1UL << UK_EFI_PAGE_SHIFT)
#define UK_EFI_PAGES_MAX		(__U64_MAX >> UK_EFI_PAGE_SHIFT)

typedef enum uk_efi_mem_type {
        UK_EFI_RESERVED_MEMORY_TYPE,
        UK_EFI_LOADER_CODE,
        UK_EFI_LOADER_DATA,
        UK_EFI_BOOT_SERVICES_CODE,
        UK_EFI_BOOT_SERVICES_DATA,
        UK_EFI_RUNTIME_SERVICES_CODE,
        UK_EFI_RUNTIME_SERVICES_DATA,
        UK_EFI_CONVENTIONAL_MEMORY,
        UK_EFI_UNUSABLE_MEMORY,
        UK_EFI_ACPI_RECLAIM_MEMORY,
        UK_EFI_ACPI_MEMORY_NVS,
        UK_EFI_MEMORY_MAPPED_IO,
        UK_EFI_MEMORY_MAPPED_IO_PORT_SPACE,
        UK_EFI_PAL_CODE,
        UK_EFI_PERSISTENT_MEMORY,
        UK_EFI_UNACCEPTED_MEMORY_TYPE,
        UK_EFI_MAX_MEMORY_TYPE
} uk_efi_mem_type_t;

typedef enum uk_efi_alloc_type {
        UK_EFI_ALLOCATE_ANY_PAGES,
        UK_EFI_ALLOCATE_MAX_ADDRESS,
        UK_EFI_ALLOCATE_ADDRESS,
        UK_EFI_MAX_ALLOCATION_TYPE
} uk_efi_alloc_type_t;

typedef enum uk_efi_timer_delay {
        UK_EFI_TIMER_CANCEL,
        UK_EFI_TIMER_PERIODIC,
        UK_EFI_TIMER_RELATIVE
} uk_efi_timer_delay_t;

typedef enum uk_efi_locate_search_type {
        UK_EFI_ALL_HANDLES,
        UK_EFI_BY_REGISTER_NOTIFY,
        UK_EFI_BY_PROTOCOL
} uk_efi_locate_search_type_t;

typedef enum uk_efi_graphics_pixel_format {
	PIXEL_RED_GREEN_BLUE_RESERVED_8BIT_PER_COLOR,
	PIXEL_BLUE_GREEN_RED_RESERVED_8BIT_PER_COLOR,
	PIXEL_BIT_MASK,
	PIXEL_BLT_ONLY,
	PIXEL_FORMAT_MASK
} uk_efi_graphics_pixel_format_t;

typedef enum uk_efi_graphics_output_blt_operation {
	UK_EFI_BLT_VIDEO_FILL,
	UK_EFI_BLT_VIDEO_TO_BLT_BUFFER,
	UK_EFI_BLT_BUFFER_TO_VIDEO,
	UK_EFI_BLT_VIDEO_TO_VIDEO,
	UK_EFI_GRAPHICS_OUTPUT_BLT_OPERATION_MAX
} uk_efi_graphics_output_blt_operation_t;

typedef struct uk_efi_mem_desc {
        __u32 type;
        __u32 pad;
        uk_efi_paddr_t physical_start;
        uk_efi_vaddr_t virtual_start;
        __u64 number_of_pages;
        __u64 attribute;
} uk_efi_mem_desc_t;

typedef struct uk_efi_dev_path_prot {
        __u8 type;
        __u8 subtype;
        __u16 len;
} uk_efi_dev_path_prot_t;

typedef struct uk_efi_open_prot_info_entry {
  uk_efi_hndl_t agent_handle;
  uk_efi_hndl_t controller_handle;
  __u32 attributes;
  __u32 open_count;
} uk_efi_open_prot_info_entry_t;

typedef	struct uk_efi_tab_hdr {
	__u64 signature;
	__u32 revision;
	__u32 header_size;
	__u32 crc32;
	__u32 reserved;
} uk_efi_tab_hdr_t;

typedef struct uk_efi_boot_services {
        uk_efi_tab_hdr_t hdr;

        uk_efi_tpl_t
        (__uk_efi_api *raise_tpl)(uk_efi_tpl_t new_tpl);

        void
        (__uk_efi_api *restore_tpl)(uk_efi_tpl_t old_tpl);

        uk_efi_status_t
        (__uk_efi_api *allocate_pages)(uk_efi_alloc_type_t a_type,
				        uk_efi_mem_type_t m_type,
                                       uk_efi_uintn_t num_pgs,
                                       uk_efi_paddr_t *paddr);

        uk_efi_status_t
        (__uk_efi_api *free_pages)(uk_efi_paddr_t paddr,
                                   uk_efi_uintn_t num_pgs);

        uk_efi_status_t
        (__uk_efi_api *get_memory_map)(uk_efi_uintn_t *map_sz,
                                       uk_efi_mem_desc_t *map,
                                       uk_efi_uintn_t *map_key,
                                       uk_efi_uintn_t *desc_sz,
                                       __u32 *desc_ver);

        uk_efi_status_t
        (__uk_efi_api *allocate_pool)(uk_efi_mem_type_t type,
                                      uk_efi_uintn_t sz,
                                      void **buf);

        uk_efi_status_t
        (__uk_efi_api *free_pool)(void *buf);

        uk_efi_status_t
        (__uk_efi_api *create_event)(__u32 type,
                                    uk_efi_tpl_t notify_tpl,
                                    void (*notify_func)(uk_efi_event_t event,
                                                        void *ctx),
                                    void *notify_ctx,
                                    uk_efi_event_t *event);

        uk_efi_status_t
        (__uk_efi_api *set_timer)(uk_efi_event_t event,
                                  uk_efi_timer_delay_t type,
                                  __u64 time);

        uk_efi_status_t
        (__uk_efi_api *wait_for_event)(uk_efi_uintn_t num_events,
                                       uk_efi_event_t *event,
                                       uk_efi_uintn_t *idx);

        uk_efi_status_t
        (__uk_efi_api *signal_event)(uk_efi_event_t event);

        uk_efi_status_t
        (__uk_efi_api *close_event)(uk_efi_event_t event);

        uk_efi_status_t
        (__uk_efi_api *check_event)(uk_efi_event_t event);

        uk_efi_status_t
        (__uk_efi_api *install_protocol_interface)(uk_efi_hndl_t hndl,
                                                   uk_efi_guid_t *prot,
                                                   uk_efi_if_type_t if_type,
                                                   void *prot_if);

        uk_efi_status_t
        (__uk_efi_api *reinstall_protocol_interface)(uk_efi_hndl_t hndl,
						     uk_efi_guid_t *prot,
                                                     void *prot_if);

        uk_efi_status_t
        (__uk_efi_api *uninstall_protocol_interface)(uk_efi_hndl_t hndl,
						     uk_efi_guid_t *prot,
						     void *prot_if);

        uk_efi_status_t
        (__uk_efi_api *handle_protocol)(uk_efi_hndl_t hndl,
					uk_efi_guid_t *prot,
					void *prot_if);

        void *reserved;

        uk_efi_status_t
        (__uk_efi_api *register_protocol_notify)(uk_efi_guid_t *prot,
                                                 uk_efi_event_t event,
                                                 void **registration);

        uk_efi_status_t
        (__uk_efi_api *locate_handle)(uk_efi_locate_search_type_t type,
                                      uk_efi_guid_t *prot,
                                      void *key,
                                      uk_efi_uintn_t *buf_sz,
                                      uk_efi_hndl_t *buf);

        uk_efi_status_t
        (__uk_efi_api *locate_device_path)(uk_efi_guid_t *prot,
                                           uk_efi_dev_path_prot_t **dev_path,
                                           uk_efi_hndl_t *dev);

        uk_efi_status_t
        (__uk_efi_api *install_configuration_table)(uk_efi_guid_t *guid,
                                                    void *tab);

        uk_efi_status_t
        (__uk_efi_api *load_image)(bool boot_policy,
                                   uk_efi_hndl_t parent_img_hndl,
                                   uk_efi_dev_path_prot_t *file_path,
                                   void *src_buf,
                                   uk_efi_uintn_t src_sz,
                                   uk_efi_hndl_t *img_hndl);

        uk_efi_status_t
        (__uk_efi_api *start_image)(uk_efi_hndl_t img_hndl,
                                    uk_efi_uintn_t *exit_data_sz,
                                    __s16 **exit_data);

        uk_efi_status_t __noreturn
        (__uk_efi_api *exit)(uk_efi_hndl_t img_hndl,
                             uk_efi_status_t exit_status,
                             uk_efi_uintn_t exit_data_size,
                             __s16 *exit_data);

        uk_efi_status_t
        (__uk_efi_api *unload_image)(uk_efi_hndl_t img_hndl);

        uk_efi_status_t
        (__uk_efi_api *exit_boot_services)(uk_efi_hndl_t img_hndl,
                                           uk_efi_uintn_t map_key);

        uk_efi_status_t
        (__uk_efi_api *get_next_monotonic_count)(__u64 *count);

        uk_efi_status_t
        (__uk_efi_api *stall)(uk_efi_uintn_t ms);

        uk_efi_status_t
        (__uk_efi_api *set_watchdog_timer)(uk_efi_uintn_t timeout,
                                           __u64 wdt_code,
                                           uk_efi_uintn_t data_sz,
                                           __s16 *wdt_data);

        uk_efi_status_t
        (__uk_efi_api *connect_controller)(uk_efi_hndl_t ctlr_hndl,
                                           uk_efi_hndl_t *drv_img_hndl,
                                           uk_efi_dev_path_prot_t *rem_dev_path,
                                           bool recursive);
        uk_efi_status_t
        (__uk_efi_api *disconnect_controller)(uk_efi_hndl_t ctlr_hndl,
                                              uk_efi_hndl_t drv_img_hndl,
                                              uk_efi_hndl_t child_hndl);
        uk_efi_status_t
        (__uk_efi_api *open_protocol)(uk_efi_hndl_t hndl,
                                      uk_efi_guid_t *prot,
                                      void **prot_if,
                                      uk_efi_hndl_t agent_hndl,
                                      uk_efi_hndl_t ctlr_hndl,
                                      __u32 attr);
        uk_efi_status_t
        (__uk_efi_api *close_protocol)(uk_efi_hndl_t hndl,
                                       uk_efi_guid_t *prot,
                                       uk_efi_hndl_t agent_hndl,
                                       uk_efi_hndl_t ctlr_hndl);

        uk_efi_status_t
        (__uk_efi_api *open_protocol_information)(uk_efi_hndl_t hndl,
                                                  uk_efi_guid_t *prot,
                                                  uk_efi_open_prot_info_entry_t *buf,
                                                  uk_efi_uintn_t num_info);

        uk_efi_status_t
        (__uk_efi_api *protocols_per_handle)(uk_efi_hndl_t hndl,
                                             uk_efi_guid_t ***prot_buf,
                                             uk_efi_uintn_t *num_prot_buf);

        uk_efi_status_t
        (__uk_efi_api *locate_handle_buffer)(uk_efi_locate_search_type_t type,
                                             uk_efi_guid_t *prot,
                                             void *key,
                                             uk_efi_uintn_t *no_hndls,
                                             uk_efi_hndl_t **buf);
        uk_efi_status_t
        (__uk_efi_api *locate_protocol)(uk_efi_guid_t *prot,
                                        void *registration,
                                        void **prot_if);

        uk_efi_status_t
        (__uk_efi_api *install_multiple_protocol_interfaces)(uk_efi_hndl_t *hndl,
                                                             ...);

        uk_efi_status_t
        (__uk_efi_api *uninstall_multiple_protocol_interfaces)(uk_efi_hndl_t *hndl,
                                                               ...);

        uk_efi_status_t
        (__uk_efi_api *calculate_crc32)(void *data,
                                        uk_efi_uintn_t data_sz,
                                        __u32 *crc32);

        void
        (__uk_efi_api *copy_mem)(void *dest,
                                 const void *src,
                                 uk_efi_uintn_t len);

        void
        (__uk_efi_api *set_mem)(void *buf,
                                uk_efi_uintn_t sz,
                                __u8 val);
} uk_efi_boot_services_t;
extern uk_efi_boot_services_t *uk_efi_bs;

typedef struct uk_efi_time_caps {
        __u32 resolution;
        __u32 accuracy;
        bool sets_to_zero;
} uk_efi_time_caps_t;

typedef enum uk_efi_reset_type {
        UK_EFI_RESET_COLD,
        UK_EFI_RESET_WARM,
        UK_EFI_RESET_SHUTDOWN
} uk_efi_reset_type_t;

typedef struct uk_efi_time {
	__u16 year;
	__u8 month;
	__u8 day;
	__u8 hour;
	__u8 minute;
	__u8 second;
	__u8 pad1;
	__u32 nanosecond;
	__s16 time_zone;
	__u8 daylight;
	__u8 pad2;
} uk_efi_time_t;

typedef struct uk_efi_runtime_services {
        uk_efi_tab_hdr_t hdr;

        uk_efi_status_t
        (__uk_efi_api *get_time)(uk_efi_time_t *time,
                                 uk_efi_time_caps_t *caps);

        uk_efi_status_t
        (__uk_efi_api *set_time)(uk_efi_time_t *time);

        uk_efi_status_t
        (__uk_efi_api *get_wakeup_time)(bool *enabled,
                                        bool *pending,
                                        uk_efi_time_t *time);

        uk_efi_status_t
        (__uk_efi_api *set_wakeup_time)(bool enabled,
                                        uk_efi_time_t *time);

        uk_efi_status_t
        (__uk_efi_api *set_virtual_address_map)(uk_efi_uintn_t mem_map_sz,
                                                uk_efi_uintn_t desc_sz,
                                                __u32 desc_ver,
                                                uk_efi_mem_desc_t *vmap);

        uk_efi_status_t
        (__uk_efi_api *convert_pointer)(uk_efi_uintn_t dbg_disposition,
                                        void **addr);

        uk_efi_status_t
        (__uk_efi_api *get_variable)(__s16 *var_name,
                                     uk_efi_guid_t *vendor_guid,
                                     __u32 *attr,
                                     uk_efi_uintn_t *data_sz,
                                     void *data);

        uk_efi_status_t
        (__uk_efi_api *get_next_variable_name)(uk_efi_uintn_t *var_name_sz,
                                               __s16 *var_name,
                                               uk_efi_guid_t *vendor_guid);

        uk_efi_status_t
        (__uk_efi_api *set_variable)(__s16 *var_name,
                                     uk_efi_guid_t *vendor_guid,
                                     __u32 attr,
                                     uk_efi_uintn_t data_sz,
                                     void *data);

        void
        (__uk_efi_api *reset_system)(uk_efi_reset_type_t type,
                                     uk_efi_status_t status,
                                     uk_efi_uintn_t data_sz,
                                     __s16 *reset_data);
} uk_efi_runtime_services_t;
extern uk_efi_runtime_services_t *uk_ef_rs;

typedef struct uk_efi_rng_prot {
        uk_efi_status_t
        (__uk_efi_api *get_info)(struct uk_efi_rng_prot *this,
                                 uk_efi_uintn_t *rng_algo_list_sz,
                                 uk_efi_guid_t *rng_algo_list);

        uk_efi_status_t
        (__uk_efi_api *set_info)(struct uk_efi_rng_prot *this,
                                 uk_efi_guid_t *rng_algo,
                                 uk_efi_uintn_t rng_val_len,
                                 __u8 *rng_val);
} uk_efi_rng_prot_t;

typedef struct uk_efi_input_key {
        __u16 scan_code;
        __s16 unicode_char;
} uk_efi_in_key_t;

typedef struct uk_efi_simple_txt_in_prot {
        uk_efi_status_t
        (__uk_efi_api *reset)(struct uk_efi_simple_txt_in_prot *this,
                              bool xverif);

        uk_efi_status_t
        (__uk_efi_api *read_key_stroke)(struct uk_efi_simple_txt_in_prot *this,
                                        uk_efi_in_key_t *key);

        uk_efi_event_t wait_for_key;
} uk_efi_simple_txt_in_prot_t;

typedef struct uk_efi_simple_out_mode {
	__s32 max_mode;
	__s32 mode;
	__s32 attribute;
	__s32 cursor_column;
	__s32 cursor_row;
	bool cursor_visible;
} uk_efi_simple_out_mode_t;

typedef struct uk_efi_simple_txt_out_prot {
	uk_efi_status_t
	(__uk_efi_api *reset)(struct uk_efi_simple_txt_out_prot *this,
			      bool xverif);

	uk_efi_status_t
	(__uk_efi_api *output_string)(struct uk_efi_simple_txt_out_prot *this,
				      __s16 *str);

	uk_efi_status_t
	(__uk_efi_api *test_string)(struct uk_efi_simple_txt_out_prot *this,
				    __s16 *str);

	uk_efi_status_t
	(__uk_efi_api *query_mode)(struct uk_efi_simple_txt_out_prot *this,
				   uk_efi_uintn_t mode_num,
				   uk_efi_uintn_t columns,
				   uk_efi_uintn_t rows);

	uk_efi_status_t
	(__uk_efi_api *set_mode)(struct uk_efi_simple_txt_out_prot *this,
				 uk_efi_uintn_t mode_num);

	uk_efi_status_t
	(__uk_efi_api *set_attribute)(struct uk_efi_simple_txt_out_prot *this,
				      uk_efi_uintn_t attr);

	uk_efi_status_t
	(__uk_efi_api *clear_screen)(struct uk_efi_simple_txt_out_prot *this);

	uk_efi_status_t
	(__uk_efi_api *set_cursor_position)(struct uk_efi_simple_txt_out_prot *this,
					    uk_efi_uintn_t column,
					    uk_efi_uintn_t row);

	uk_efi_status_t
	(__uk_efi_api *enable_cursor)(struct uk_efi_simple_txt_out_prot *this,
				      bool visible);

	uk_efi_simple_out_mode_t *mode;
} uk_efi_simple_txt_out_prot_t;

typedef struct uk_efi_cfg_tab {
	uk_efi_guid_t vendor_guid;
	void *vendor_table;
} uk_efi_cfg_tab_t;

typedef struct uk_efi_sys_tab {
        uk_efi_tab_hdr_t hdr;
        __s16 *firmware_vendor;
        __u32 firmware_revision;
        uk_efi_hndl_t console_in_handle;
        uk_efi_simple_txt_in_prot_t *con_in;
        uk_efi_hndl_t console_out_hande;
	uk_efi_simple_txt_out_prot_t *con_out;
	uk_efi_hndl_t standad_error_handle;
	uk_efi_simple_txt_out_prot_t *std_err;
	uk_efi_runtime_services_t *runtime_services;
	uk_efi_boot_services_t *boot_services;
	uk_efi_uintn_t number_of_table_entries;
	uk_efi_cfg_tab_t configuration_table;
} uk_efi_sys_tab_t;
extern uk_efi_sys_tab_t *uk_efi_st;

#define UK_EFI_LOADED_IMAGE_PROTOCOL_GUID					\
	&(uk_efi_guid_t){							\
		.b0_3 = 0x5B1B31A1,						\
		.b4_5 = 0x9562,							\
		.b6_7 = 0x11d2,							\
		.b8_15 = {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B},	\
	}

typedef struct uk_efi_ld_img_hndl {
        __u32 revision;
	uk_efi_hndl_t parent_handle;
	uk_efi_sys_tab_t *system_table;
	uk_efi_hndl_t device_handle;
	void *file_path;
	void *reserved;
	__u32 load_options_size;
        void *load_options;
	void *image_base;
	__u64 image_size;
	uk_efi_mem_type_t image_code_type;
	uk_efi_mem_type_t image_data_type;
	uk_efi_status_t	(__uk_efi_api *unload)(uk_efi_hndl_t img_hndl);
} uk_efi_ld_img_hndl_t;

typedef struct uk_efi_graphics_output_blt_pixel {
  __u8 blue;
  __u8 green;
  __u8 red;
  __u8 reserved;
} uk_efi_graphics_output_blt_pixel_t;

typedef struct uk_efi_pixel_bitmask {
	__u32	red_mask;
	__u32	green_mask;
	__u32	blue_mask;
	__u32	reserved_mask;
} uk_efi_pixel_bitmask_t;

#define UK_EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID					\
	&(uk_efi_guid_t){							\
		.b0_3 = 0x9042a9de,						\
		.b4_5 = 0x23dc,							\
		.b6_7 = 0x4a38,							\
		.b8_15 = {0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A},	\
	}

typedef struct uk_efi_grarphics_output_mode_information {
	__u32 version;
	__u32 horizontal_resolution;
	__u32 verical_resolution;
	uk_efi_graphics_pixel_format_t pixel_format;
	uk_efi_pixel_bitmask_t pixel_information;
	__u32 pixels_per_scan_line;
} uk_efi_grarphics_output_mode_information_t;

typedef struct uk_efi_graphics_output_protocol_mode {
	__u32 max_mode;
	__u32 mode;
	uk_efi_grarphics_output_mode_information_t *info;
	uk_efi_uintn_t size_of_info;
	uk_efi_paddr_t frame_buffer_base;
	uk_efi_uintn_t frame_buffer_size;
} uk_efi_graphics_output_protocol_mode_t;

typedef struct uk_efi_graphics_output_protocol {
        uk_efi_status_t
        (__uk_efi_api *query_mode)(struct uk_efi_graphics_output_protocol *this,
                                   __u32 mode_num,
                                   uk_efi_uintn_t *info_sz,
                                   uk_efi_grarphics_output_mode_information_t **info);

        uk_efi_status_t
        (__uk_efi_api *set_mode)(struct uk_efi_graphics_output_protocol *this,
				 __u32 mode_num);

        uk_efi_status_t
        (__uk_efi_api *blt)(struct uk_efi_graphics_output_protocol *this,
                            uk_efi_graphics_output_blt_pixel_t *blt_buf,
                            uk_efi_graphics_output_blt_operation_t blt_op,
                            uk_efi_uintn_t src_x,
                            uk_efi_uintn_t src_y,
                            uk_efi_uintn_t dest_x,
                            uk_efi_uintn_t dest_y,
                            uk_efi_uintn_t width,
                            uk_efi_uintn_t height,
                            uk_efi_uintn_t delta);

        uk_efi_graphics_output_protocol_mode_t *mode;
} uk_efi_graphics_output_protocol_t;

#endif /* __PLAT_CMN_EFI_H__ */
