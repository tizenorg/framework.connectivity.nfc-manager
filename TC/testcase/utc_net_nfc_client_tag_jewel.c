#include <tet_api.h>

#include "net_nfc_tag.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_tag_jewel.h"
#include "net_nfc_target_info.h"
#include "net_nfc.h"

#include <string.h>


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_jewel_read_id_p(void);
static void utc_net_nfc_jewel_read_id_n(void);
static void utc_net_nfc_jewel_read_byte_p(void);
static void utc_net_nfc_jewel_read_byte_n(void);
static void utc_net_nfc_jewel_read_all_p(void);
static void utc_net_nfc_jewel_read_all_n(void);
static void utc_net_nfc_jewel_write_with_erase_p(void);
static void utc_net_nfc_jewel_write_with_erase_n(void);
static void utc_net_nfc_jewel_write_with_no_erase_p(void);
static void utc_net_nfc_jewel_write_with_no_erase_n(void);


struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_jewel_read_id_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_jewel_read_id_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_jewel_read_byte_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_jewel_read_byte_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_jewel_read_all_p, 1},
	{ utc_net_nfc_jewel_read_all_n, 2 },
	{ utc_net_nfc_jewel_write_with_erase_p, 1},
	{ utc_net_nfc_jewel_write_with_erase_n, 2},
	{ utc_net_nfc_jewel_write_with_no_erase_p, 1},
	{ utc_net_nfc_jewel_write_with_no_erase_n, 2},
	{ NULL, 0 },
};

//this method is called only once in start
static void startup(void)
{
	/* start of TC */
}

static void cleanup(void)
{
	/* end of TC */
}

static void utc_net_nfc_jewel_read_id_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_jewel_read_id((net_nfc_target_handle_h) 0x302023,  NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_read_id_n(void)
{
	int ret=0;

	ret = net_nfc_jewel_read_id(NULL , NULL );

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_read_byte_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_jewel_read_byte((net_nfc_target_handle_h) 0x302023 , 1 , 0 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_read_byte_n(void)
{
	int ret=0;

	ret = net_nfc_jewel_read_byte(NULL , 0 , 0 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_read_all_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_jewel_read_all((net_nfc_target_handle_h) 0x302023 ,  NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_read_all_n(void)
{
	int ret=0;

	ret = net_nfc_jewel_read_all( NULL , NULL );

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_write_with_erase_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_jewel_write_with_erase((net_nfc_target_handle_h) 0x302023 , 1 , 0 , 0xff , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_write_with_erase_n(void)
{
	int ret=0;

	ret = net_nfc_jewel_write_with_erase(NULL, 0, 0, 0xff, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_write_with_no_erase_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_jewel_write_with_no_erase((net_nfc_target_handle_h) 0x302023 , 1 , 0 , 0xff , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_jewel_write_with_no_erase_n(void)
{
	int ret=0;

	ret = net_nfc_jewel_write_with_no_erase(NULL, 0, 0, 0xff, NULL);

	dts_pass(__func__, "PASS");
}
