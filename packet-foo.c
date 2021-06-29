#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 14242

static int proto_foo = -1;
static int hf_foo_function_code = -1;
static int hf_foo_sequence = -1;
static int hf_foo_fragment_flag = -1;
static int hf_foo_payload_length = -1;
static gint ett_foo = -1;
static gint ett_hdr_foo = -1;



static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    proto_tree *foo_hdr_tree, *foo_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lidgren");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    foo_tree = proto_item_add_subtree(ti, ett_foo);

    /* Create header subtree */
    foo_hdr_tree = proto_tree_add_subtree(foo_tree, tvb, 0, 4, ett_hdr_foo, NULL, "Header");

    proto_tree_add_item(foo_hdr_tree, hf_foo_function_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_hdr_tree, hf_foo_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
    
    proto_tree_add_item(foo_hdr_tree, hf_foo_fragment_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_hdr_tree, hf_foo_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return tvb_captured_length(tvb);
}


void
proto_register_foo(void)
{
    static hf_register_info hf[] = {
        { &hf_foo_function_code,
            { "Function", "foo.function",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_sequence,
            { "Message Sequence Number", "foo.sequence",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_fragment_flag,
            { "Fragment Flag", "foo.fragmentflag",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_payload_length,
            { "Payload Length", "foo.payloadlen",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        }
    };
    

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_foo,
        &ett_hdr_foo
    };

    proto_foo = proto_register_protocol (
        "Lidgren Protocol", /* name        */
        "Lidgren",          /* short name  */
        "lidgren"           /* filter_name */
        );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
