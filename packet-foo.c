#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 14242

static int proto_foo = -1;
static int hf_foo_pdu_type = -1;
static gint ett_foo = -1;



static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}


void
proto_register_foo(void)
{
    proto_foo = proto_register_protocol (
        "FOO Protocol", /* name        */
        "FOO",          /* short name  */
        "foo"           /* filter_name */
        );
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
