/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"
#include "monitor/bt.h"


#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/hci.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"


#define UUID_DEVICE_INFO 0x180A
#define UUID_USER_CHAR   0x9999

static struct hci_dev_info hdi;
static int ctl;
static pthread_t thread_id;
static int wifi_configured = 0;
static struct server *server;

#define ATT_CID 4

#define PRLOG(...) \
	do { \
		printf(__VA_ARGS__); \
		print_prompt(); \
	} while (0)



#define COLOR_OFF	"\x1B[0m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_GREEN	"\x1B[0;92m"
#define COLOR_YELLOW	"\x1B[0;93m"
#define COLOR_BLUE	"\x1B[0;94m"
#define COLOR_MAGENTA	"\x1B[0;95m"
#define COLOR_BOLDGRAY	"\x1B[1;30m"
#define COLOR_BOLDWHITE	"\x1B[1;37m"


static bool verbose = false;

struct server {
	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;
	struct gatt_db_attribute *chara_att;
	uint16_t chara_handle;
};

/*******************config wifi zone************************************************/
char start[1] = {0x01};
char magic[10] = "amlogicble";
char cmd[9] = "wifisetup";
char ssid[32] = {0};
char psk[32] = {0};
char end[1] = {0x04};
#define FRAME_BUF_MAX (1+10+9+32+32+1)
char version[8] = "20171211";
char frame_buf[FRAME_BUF_MAX] = {0};
char ssid_psk_file[] = "/var/www/cgi-bin/wifi/select.txt";
/*0: wifi set success, 1: wifi set fail*/
char wifi_status_file[] = "/etc/bsa/config/wifi_status";
char wifi_status = 0;
char wifi_success = '1';
void ble_init(void);

int config_wifi(const uint8_t *arg, int len)
{
	int ret = 0;
	int check_0 = 0;
	FILE *fd;


	if (len > 0) {
		memset(frame_buf, 0, FRAME_BUF_MAX);
		memcpy(frame_buf, arg, len);
		printf("frame_buf:%s, len:%d", frame_buf, len);
		check_0 = 0;
		if ((frame_buf[0] == 0x01)
				&& (frame_buf[FRAME_BUF_MAX-1] == 0X04)) {
			printf("frame start and end is right\n");
			if (!strncmp(magic, frame_buf+1, 10)) {
				printf("magic : %s", magic);
				printf("version : %s", version);
				check_0 = 1;
			} else {
				printf("magic of frame error!!!\n");
				memset(frame_buf, 0, FRAME_BUF_MAX);
				check_0 = 0;
			}
		} else {
			printf("start or end of frame error!!!\n");
			memset(frame_buf, 0, FRAME_BUF_MAX);
			check_0 = 0;
		}
		if (check_0 == 1) {
			if (!strncmp("wifisetup", frame_buf+11, 9)) {
				strncpy(ssid, frame_buf+20, 32);
				strncpy(psk, frame_buf+52, 32);
				printf("WiFi setup,ssid:%s,psk:%s", ssid, psk);
				system("rm -rf /var/www/cgi-bin/wifi/select.txt");
				system("touch /var/www/cgi-bin/wifi/select.txt");
				system("chmod 644 /var/www/cgi-bin/wifi/select.txt");
				fd = fopen(ssid_psk_file, "wb");
				ret = fwrite(ssid, strlen(ssid), 1, fd);
				if (ret != strlen(ssid)) {
					printf("write wifi ssid error\n");
				}
				ret = fwrite("\n", 1, 1, fd);
				if (ret != 1) {
					printf("write enter and feedline error\n");
				}
				ret = fwrite(psk, strlen(psk), 1, fd);
				if (ret != strlen(psk)) {
					printf("write wifi password error\n");
				}
				fflush(fd);
				check_0 = 0;
				memset(frame_buf, 0, FRAME_BUF_MAX);
				fclose(fd);
				wifi_configured = 1;

			}
		}
	}
	return 0;
}

/*******************config wifi zone end*********************************************/
static struct bt_hci *hci_dev;

static void print_prompt(void)
{
	printf(COLOR_BLUE "[GATT server]" COLOR_OFF "# ");
	fflush(stdout);
}



static void att_disconnect_cb(int err, void *user_data)
{
	printf("Device disconnected: %s\n", strerror(err));

	mainloop_quit();
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_BOLDGRAY "%s" COLOR_BOLDWHITE "%s\n" COLOR_OFF, prefix,
			str);
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_GREEN "%s%s\n" COLOR_OFF, prefix, str);
}

static void user_service_read_cb(struct gatt_db_attribute *attrib,
		unsigned int id, uint16_t offset,
		uint8_t opcode, struct bt_att *att,
		void *user_data)
{

	//	printf("user_service_read_cb\n");

	gatt_db_attribute_read_result(attrib, id, 0, &wifi_status, 1);
}

static void user_service_write_cb(struct gatt_db_attribute *attrib,
		unsigned int id, uint16_t offset,
		const uint8_t *value, size_t len,
		uint8_t opcode, struct bt_att *att,
		void *user_data)
{
	int i;
	struct server *server = (struct server *)user_data;
	printf("%s enter, data len =%d\n", __func__, len);
	config_wifi(value, len);

	gatt_db_attribute_write_result(attrib, id, 0);

}


static void populate_user_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *characteristic;

	bt_uuid16_create(&uuid, UUID_DEVICE_INFO);
	service = gatt_db_add_service(server->db, &uuid, true, 8);


	bt_uuid16_create(&uuid, UUID_USER_CHAR);
	server->chara_att = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
			BT_GATT_CHRC_PROP_NOTIFY | BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_INDICATE | BT_GATT_CHRC_PROP_READ,
			user_service_read_cb,
			user_service_write_cb,
			server);
	server->chara_handle = gatt_db_attribute_get_handle(characteristic);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
			BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
			NULL, NULL, NULL);

	gatt_db_service_set_active(service, true);
}



static struct server *server_create(int fd)
{
	struct server *server;

	server = new0(struct server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for server\n");
		return NULL;
	}

	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, NULL,
				NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}


	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, 0);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	if (verbose) {
		bt_att_set_debug(server->att, att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb,
				"server: ", NULL);
	}

	/* Random seed for generating fake Heart Rate measurements */
	srand(time(NULL));

	/* bt_gatt_server already holds a reference */
	populate_user_service(server);

	return server;

fail:
	gatt_db_unref(server->db);
	bt_att_unref(server->att);
	free(server);

	return NULL;
}

static void server_destroy(struct server *server)
{
	bt_gatt_server_unref(server->gatt);
	gatt_db_unref(server->db);
}



static int l2cap_le_att_listen_and_accept(bdaddr_t *src, int sec,
		uint8_t src_type)
{
	int sk, nsk, i;
	struct sockaddr_l2 srcaddr, addr;
	socklen_t optlen;
	struct bt_security btsec;
	char ba[18];

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);
	printf("\n");
	if (bind(sk, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &btsec,
				sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(sk, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	printf("Started listening on ATT channel. Waiting for connections\n");

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		perror("Accept failed");
		goto fail;
	}

	ba2str(&addr.l2_bdaddr, ba);
	printf("Connect from %s\n", ba);
	close(sk);

	return nsk;

fail:
	close(sk);
	return -1;
}


static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			mainloop_quit();
			break;
		default:
			break;
	}
}

static void send_cmd(int cmd, void *params, int params_len)
{
	struct hci_request rq;
	uint8_t status;
	int dd, ret, hdev;

	if (hdev < 0)
		hdev = hci_get_route(NULL);

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}


	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = cmd;
	rq.cparam = params;
	rq.clen = params_len;
	rq.rparam = &status;
	rq.rlen = 1;

	ret = hci_send_req(dd, &rq, 1000);

done:
	hci_close_dev(dd);

	if (ret < 0) {
		fprintf(stderr, "Can't send cmd 0x%x to hci%d: %s (%d)\n", cmd,
				hdev, strerror(errno), errno);
		exit(1);
	}

	if (status) {
		fprintf(stderr,
				"LE cmd 0x%x on hci%d returned status %d\n", cmd,
				hdev, status);
		exit(1);
	}
}


static void clear_adv_set(void)
{
	int temp = 10;
	send_cmd(BT_HCI_CMD_LE_CLEAR_ADV_SETS,  &temp, 1);
}


static void set_adv_data(void)
{
	struct bt_hci_cmd_le_set_adv_data param;
	//complete local name: 0x04, 0x09, 0x41, 0x4d, 0x4c (AML)
	uint8_t data[] = {0x02, 0x1, 0x06, 0x03, 0x03, 0x0a, 0x18,0x04, 0x09, 0x41, 0x4d, 0x4c, 0x08, 0x1b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	// advertise public mac addr
	memset(&param, 0, sizeof(param));

	memcpy(data + sizeof(data) - 6, hdi.bdaddr.b, 6);


	param.len = sizeof(data);
	memcpy(param.data, data , param.len);

	send_cmd(BT_HCI_CMD_LE_SET_ADV_DATA, (void *)&param, sizeof(param));


}


static void set_adv_response(void)
{
	struct bt_hci_cmd_le_set_scan_rsp_data param;

	//clear response
	memset(&param, 0, sizeof(param));
	send_cmd(BT_HCI_CMD_LE_SET_SCAN_RSP_DATA, (void *)&param, sizeof(param));


}


static void set_adv_parameters(void)
{
	struct bt_hci_cmd_le_set_adv_parameters param;

#if 1
	struct bt_hci_cmd_le_set_random_address r_bddr;

	memcpy(r_bddr.addr, hdi.bdaddr.b, 6);
	r_bddr.addr[0] += 0x04;
	r_bddr.addr[1] += 0x04;

	send_cmd(BT_HCI_CMD_LE_SET_RANDOM_ADDRESS, (void *)&r_bddr, sizeof(r_bddr));
#endif
	param.min_interval = cpu_to_le16(0x0020);
	param.max_interval = cpu_to_le16(0x0020);
	param.type = 0x00;		/* connectable no-direct advertising */
	param.own_addr_type = 0x01;	/* Use random address */
	//param.own_addr_type = 0x00;	/* Use public address */
	param.direct_addr_type = 0x00;
	memset(param.direct_addr, 0, 6);
	param.channel_map = 0x07;
	param.filter_policy = 0x00;


	send_cmd(BT_HCI_CMD_LE_SET_ADV_PARAMETERS, (void *)&param, sizeof(param));

}

static void set_adv_enable(int enable)
{
	struct bt_hci_cmd_le_set_adv_enable param;
	if (enable !=0 && enable != 1) {
		printf("%s: invalid arg: \n", __func__, enable);
		return;
	}
	param.enable = enable;
	send_cmd(BT_HCI_CMD_LE_SET_ADV_ENABLE, (void *)&param, sizeof(param));


}

void ble_init(void)
{
	set_adv_enable(0);
	set_adv_data();
	set_adv_parameters();
	set_adv_response();
	set_adv_enable(1);
}



void hci_dev_init(void)
{

	/* Open HCI socket	*/
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}

	hdi.dev_id = 0;

	if (ioctl(ctl, HCIGETDEVINFO, (void *) &hdi)) {
		perror("Can't get device info");
		exit(1);
	}

}


static void *check_wifi_status(void *user_data)
{
	bool result;
	uint8_t status = 0;
	FILE *fd;
	int ret;

	while (1) {
		if (wifi_configured) {
			printf("wifi configured\n");
			system("sh /etc/bsa/config/wifi_tool.sh");
			fd = fopen(wifi_status_file, "r+");
			if (fd <= 0) {
				printf("read wifi status file error\n");
			}
			ret = fread(&status, 1, 1, fd);
			if (ret == 1) {
				if (!strncmp(&status, &wifi_success, 1)) {
					wifi_status = 1;
					printf("wifi setup success, and then exit ble mode\n");
					sleep(5);
					system("sh /usr/bin/bluez_tool.sh restart &");
					exit(0);
				} else {
					wifi_status = 2;
					printf("status not ok: %c , configure wifi fail!\n", status);
				}
			}
			fclose(fd);

			status = 0;
			wifi_configured = 0;
		}
		sleep(2);
	}

	printf("%s thread exit\n", __func__);
}


int main(int argc, char *argv[])
{

	bdaddr_t src_addr;
	int fd;
	int sec = BT_SECURITY_LOW;
	uint8_t src_type = BDADDR_LE_PUBLIC;
	sigset_t mask;


	if (argc > 1) {
		if (strcmp(argv[1], "-v") == 0)
			verbose= true;
	}

	hci_dev_init();

	ble_init();

	bacpy(&src_addr, BDADDR_ANY);
	fd = l2cap_le_att_listen_and_accept(&src_addr, sec, src_type);
	if (fd < 0) {
		fprintf(stderr, "Failed to accept L2CAP ATT connection\n");
		return EXIT_FAILURE;
	}

	mainloop_init();

	server = server_create(fd);
	if (!server) {
		close(fd);
		return EXIT_FAILURE;
	}


	pthread_create(&thread_id, NULL, check_wifi_status, server);

	printf("Running GATT server\n");

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_cb, NULL, NULL);

	mainloop_run();

	printf("\n\nShutting down...\n");

	server_destroy(server);
	pthread_cancel(thread_id);

	return EXIT_SUCCESS;
}
