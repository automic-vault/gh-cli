#include <xpc/xpc.h>

extern void av_approval_event(const char *event_name);

void av_xpc_connection_set_event_handler(xpc_connection_t connection) {
	xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
		if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) return;
		const char *event_name = xpc_dictionary_get_string(event, "event");
		if (event_name != NULL) av_approval_event(event_name);
	});
}
