#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"

#include "gdbus/gdbus.h"

#include "src/dbus-common.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/log.h"

/********************************************************************/
/*Dev startegy:														*/
/*0: not strategy, no limit to connected device number				*/
/*																	*/
/*1: only one connected device allowed,								*/
/*   always reject next device till prev device disconnected		*/
/*																	*/
/*2: only one connected device allowed,								*/
/*   disconnect prev device when next device request connection		*/
/********************************************************************/
#define DEV_STRATEGY 2

#define RESERVED_DEVICE_FILE "/etc/bluetooth/reserved_device"
static GDBusClient *client = NULL;
static GDBusProxy *adapter_proxy = NULL;
static GDBusProxy *reserved_device_proxy = NULL;
static const char *reserved_device_path = NULL;
static GList *dev_list = NULL;
static char SRT[2] = {5, 2};		//Startup reconnect timeout

static gboolean connect_dev(void* user_data);
static void connect_dev_return(DBusMessage *message, void *user_data);

static void save_reserved_device()
{
	FILE *fp;
	const char *obj_path;

	if (!reserved_device_proxy) {
		info("reserved_device_proxy is NULL");
		return;
	}

	obj_path = g_dbus_proxy_get_path(reserved_device_proxy);

	info("reserved device obj_path = %s\n", obj_path);

	fp = fopen(RESERVED_DEVICE_FILE, "w");
	if (fp  == NULL) {
		error("open %s: %s", RESERVED_DEVICE_FILE, strerror(errno));
		return;
	}

	fwrite(obj_path, strlen(obj_path), 1, fp);

	fclose(fp);

}

static const char* get_reserved_device()
{
	FILE *fp;
	static char obj_path[] = "/org/bluez/hci0/dev_xx_xx_xx_xx_xx_xx";


	fp = fopen(RESERVED_DEVICE_FILE, "r");
	if (fp  == NULL) {
		error("open %s: %s", RESERVED_DEVICE_FILE, strerror(errno));
		return obj_path;
	}

	fread(obj_path, sizeof(obj_path), 1, fp);

	fclose(fp);

	info("reserved device obj_path readed = %s\n", obj_path);

	return obj_path;

}

static int set_discoverable(int enable)
{
	dbus_bool_t value;
	DBusMessageIter iter;

	if (!adapter_proxy) {
		error("Enable/Disable disacoverable fail, org.bluez.Adapter1 not registered yet!");
		return -1;
	}

	if (enable) {
		info("Set local device discoverable");
		value = TRUE;
	} else {
		info("Set local device undiscoverable");
		value = FALSE;
	}

	g_dbus_proxy_set_property_basic(adapter_proxy,
									"Discoverable",
									DBUS_TYPE_BOOLEAN,
									&value,
									NULL,
									NULL,
									NULL);
	return 0;
}

static int set_pairable(int enable)
{
	dbus_bool_t value;
	DBusMessageIter iter;

	if (!adapter_proxy) {
		error("Enable/Disable pairable fail, org.bluez.Adapter1 not registered yet!");
		return -1;
	}

	if (enable) {
		info("Set local device pairable");
		value = TRUE;
	} else {
		info("Set local device unpairable");
		value = FALSE;
	}

	g_dbus_proxy_set_property_basic(adapter_proxy,
									"Pairable",
									DBUS_TYPE_BOOLEAN,
									&value,
									NULL,
									NULL,
									NULL);
	return 0;
}

static void connect_dev_return(DBusMessage *message, void *user_data)
{

	DBusError error;
	static int cnt = 3;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, message) == TRUE) {
		info("%s get msg: %s", __func__, error.name);

		if (strstr(error.name, "Failed") && (cnt > 0)) {
			info("%s reset timer", __func__);
			cnt--;
			g_timeout_add_seconds(SRT[1], connect_dev, user_data);

		}
		dbus_error_free(&error);
	}
}

static gboolean connect_dev(void* user_data)
{
	GDBusProxy *proxy = (GDBusProxy *) user_data;
	DBusMessageIter iter;

	info("Startup reconnection begin!!");

	if (!proxy) {
		error("Connecet device  fail, invalid proxy!");
		return FALSE;
	}

	if (g_list_length(dev_list) > 0) {
		error("Device connected already, return!");
		return FALSE;

	}

	info("Connect target device: %s", g_dbus_proxy_get_path(proxy));

	if (g_dbus_proxy_method_call(proxy,
								 "Connect",
								 NULL,
								 connect_dev_return,
								 user_data,
								 NULL) == FALSE) {
		error("Failed to call org.bluez.Device1.Connect");
	}

	//not matter what, stop timer
	return FALSE;
}

static int disconnect_prev_dev()
{
	DBusMessageIter iter;

	GList *temp = g_list_last(dev_list)->prev;

	info("Disconnect earlier connected device");

	while (temp) {
		GDBusProxy *proxy = (GDBusProxy *)temp->data;
		info("Disconnecting device, obj_path = %s\n", g_dbus_proxy_get_path(proxy));
		if (g_dbus_proxy_method_call(proxy,
									 "Disconnect",
									 NULL,
									 NULL,
									 NULL,
									 NULL) == FALSE) {
			error("Failed to call org.bluez.Device1.Disconnect");
		}
		temp = temp->prev;
	}

	return 0;
}

static int disconnect_next_dev()
{
	DBusMessageIter iter;
	GList *temp = g_list_first(dev_list)->next;

	info("Disconnect later connected device");

	while (temp) {
		GDBusProxy *proxy = (GDBusProxy *)temp->data;
		info("Disconnecting device, obj_path = %s\n", g_dbus_proxy_get_path(proxy));
		if (g_dbus_proxy_method_call(proxy,
									 "Disconnect",
									 NULL,
									 NULL,
									 NULL,
									 NULL) == FALSE) {
			error("Failed to call org.bluez.Device1.Disconnect");
		}
		temp = temp->next;
	}

	return 0;
}

static int strategy_excute()
{
	int dev_num = g_list_length(dev_list);

	info("Connected device number = %d", dev_num);
#if (DEV_STRATEGY == 1)
	if (g_list_first(dev_list))
		reserved_device_proxy = (GDBusProxy *)g_list_first(dev_list)->data;
	else
		reserved_device_proxy = NULL;

	if (dev_num > 1)
		disconnect_next_dev();

	if (dev_num > 0)
		set_discoverable(0);
	else
		set_discoverable(1);

#elif (DEV_STRATEGY == 2)
	if (g_list_last(dev_list))
		reserved_device_proxy = (GDBusProxy *)g_list_last(dev_list)->data;
	else
		reserved_device_proxy = NULL;

	if (dev_num > 1)
		disconnect_prev_dev();
#endif

	save_reserved_device();

	return 0;

}

static void property_changed(GDBusProxy *proxy, const char *name,
							 DBusMessageIter *iter, void *user_data)
{
	const char *interface;
	dbus_bool_t valbool;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1")) {
		if (!strcmp(name, "Connected")) {
			dbus_message_iter_get_basic(iter, &valbool);
			info("%s, Connectd status changed:  %s\n", g_dbus_proxy_get_path(proxy), valbool == TRUE ? "TRUE" : "FALSE");
			if (TRUE == valbool) {
				dev_list = g_list_append(dev_list, proxy);
			} else {
				dev_list = g_list_remove(dev_list, proxy);
			}
			strategy_excute();
		}
	}
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;
	DBusMessageIter iter;
	dbus_bool_t valbool;
	static int startup = 1;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1")) {
		const char *obj_path =  g_dbus_proxy_get_path(proxy);
		info("org.bluez.Device1 registered: %s\n", obj_path);
		if (TRUE == g_dbus_proxy_get_property(proxy, "Connected", &iter)) {
			dbus_message_iter_get_basic(&iter, &valbool);
			if (TRUE == valbool) {
				dev_list = g_list_append(dev_list, proxy);
				strategy_excute();
			} else {
				/*If device is found in startup and is reserved_device
				  we will reconnect it*/
				if (!strcmp(obj_path, reserved_device_path) && startup) {
					info("Going to reconnect last connected device!");
					startup = 0;
					//create a timer call connect_dev later
					g_timeout_add_seconds(SRT[0], connect_dev, (void *)proxy);
				}
			}
		}

	}

	if (!strcmp(interface, "org.bluez.Adapter1"))
		adapter_proxy = proxy;

}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;
	DBusMessageIter iter;

	interface = g_dbus_proxy_get_interface(proxy);
	if (!strcmp(interface, "org.bluez.Device1")) {
		info("org.bluez.Device1 removed: %s\n", g_dbus_proxy_get_path(proxy));
	}

	if (!strcmp(interface, "org.bluez.Adapter1"))
		adapter_proxy = NULL;
}

static int dev_strategy_probe(struct btd_adapter *adapter)
{
	DBG("");
	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed, property_changed, NULL);

	return 0;
}

static void dev_strategy_remove(struct btd_adapter *adapter)
{
	DBG("");
}

static struct btd_adapter_driver dev_strategy_driver = {
	.name 	= "dev_strategy",
	.probe 	= dev_strategy_probe,
	.remove	= dev_strategy_remove,
};

static int dev_strategy_init(void)
{
	int err = 0;
#if (DEV_STRATEGY > 0)
	DBusConnection *conn = btd_get_dbus_connection();

	DBG("");
	info("dev_strategy%d starting work!!", DEV_STRATEGY);

	client =  g_dbus_client_new(conn, "org.bluez", "/org/bluez");

	err = btd_register_adapter_driver(&dev_strategy_driver);
	if (err < 0) {
		g_dbus_client_unref(client);
		error("Failed to register btd driver\n");
	}

	reserved_device_path = get_reserved_device();

#else
	info("dev_strategy won't work!!");
#endif

	return err;
}

static void dev_strategy_exit(void)
{
	DBG("");
#if (DEV_STRATEGY > 0)
	btd_unregister_adapter_driver(&dev_strategy_driver);

	if (client) {
		g_dbus_client_unref(client);
		client = NULL;
	}

	if (dev_list) {
		g_list_free(dev_list);
		dev_list = NULL;
	}

#endif
}

BLUETOOTH_PLUGIN_DEFINE(dev_strategy, VERSION,
						BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, dev_strategy_init, dev_strategy_exit)
