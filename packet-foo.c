#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-rdm.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>



//#define FOO_PORT 14249//14242

//#define OPTIONAL TRUE
#define FRAME_HEADER_LEN 10
#define IP_PROTO_foo 254

static int proto_foo = -1;
static int hf_foo_function_code = -1;
static int hf_foo_sequence = -1;
static int hf_foo_fragment_flag = -1;
static int hf_foo_payload_length = -1;
static gint ett_foo = -1;
static gint ett_hdr_foo = -1;
static dissector_handle_t foo_pdu_handle;
static dissector_handle_t foo_udp_handle;
static dissector_handle_t foo_tcp_handle;
conversation_t *conversation;


const value_string lidgren_func_vals[] = {
    {0, "Unconnected"},
    {1, "userUnreliable"},
    {2, "UserSequenced1"},
    {3, "UserSequenced1"},
    {4, "UserSequenced1"},
    {5, "UserSequenced1"},
    {6, "UserSequenced1"},
    {7, "UserSequenced1"},
    {8, "UserSequenced1"},
    {9, "UserSequenced1"},
    {10, "UserSequenced1"},
    {11, "UserSequenced1"},
    {12, "UserSequenced1"},
    {13, "UserSequenced1"},
    {14, "UserSequenced1"},
    {15, "UserSequenced1"},
    {16, "UserSequenced1"},
    {17, "UserSequenced1"},
    {18, "UserSequenced1"},
    {19, "UserSequenced1"},
    {20, "UserSequenced1"},
    {21, "UserSequenced1"},
    {22, "UserSequenced1"},
    {23, "UserSequenced1"},
    {24, "UserSequenced1"},
    {25, "UserSequenced1"},
    {26, "UserSequenced1"},
    {27, "UserSequenced1"},
    {28, "UserSequenced1"},
    {29, "UserSequenced1"},
    {30, "UserSequenced1"},
    {31, "UserSequenced1"},
    {32, "UserSequenced1"},
    {33, "UserSequenced1"},

    {34, "UserRealiableUnordered"},
    {35, "UserRealiableUnordered"},
    {36, "UserRealiableUnordered"},
    {37, "UserRealiableUnordered"},
    {38, "UserRealiableUnordered"},
    {39, "UserRealiableUnordered"},
    {40, "UserRealiableUnordered"},
    {31, "UserRealiableUnordered"},
    {32, "UserRealiableUnordered"},
    {33, "UserRealiableUnordered"},
    {34, "UserRealiableUnordered"},
    {35, "UserRealiableUnordered"},
    {36, "UserRealiableUnordered"},
    {37, "UserRealiableUnordered"},
    {38, "UserRealiableUnordered"},
    {39, "UserRealiableUnordered"},
    {40, "UserRealiableUnordered"},
    {41, "UserRealiableUnordered"},
    {42, "UserRealiableUnordered"},
    {43, "UserRealiableUnordered"},
    {44, "UserRealiableUnordered"},
    {45, "UserRealiableUnordered"},
    {46, "UserRealiableUnordered"},
    {47, "UserRealiableUnordered"},
    {48, "UserRealiableUnordered"},
    {49, "UserRealiableUnordered"},
    {50, "UserRealiableUnordered"},
    {51, "UserRealiableUnordered"},
    {52, "UserRealiableUnordered"},
    {53, "UserRealiableUnordered"},
    {54, "UserRealiableUnordered"},
    {55, "UserRealiableUnordered"},
    {56, "UserRealiableUnordered"},
    {57, "UserRealiableUnordered"},
    {58, "UserRealiableUnordered"},
    {59, "UserRealiableUnordered"},
    {60, "UserRealiableUnordered"},
    {61, "UserRealiableUnordered"},
    {62, "UserRealiableUnordered"},
    {63, "UserRealiableUnordered"},
    {64, "UserRealiableUnordered"},
    {65, "UserRealiableUnordered"},
    {66, "UserRealiableUnordered"},

    {67, "UserReliableOrdered1"},
    {68, "UserReliableOrdered1"},
    {69, "UserReliableOrdered1"},
    {70, "UserReliableOrdered1"},
    {71, "UserReliableOrdered1"},
    {72, "UserReliableOrdered1"},
    {73, "UserReliableOrdered1"},
    {74, "UserReliableOrdered1"},
    {75, "UserReliableOrdered1"},
    {76, "UserReliableOrdered1"},
    {77, "UserReliableOrdered1"},
    {78, "UserReliableOrdered1"},
    {79, "UserReliableOrdered1"},
    {80, "UserReliableOrdered1"},
    {81, "UserReliableOrdered1"},
    {82, "UserReliableOrdered1"},
    {83, "UserReliableOrdered1"},
    {84, "UserReliableOrdered1"},
    {85, "UserReliableOrdered1"},
    {86, "UserReliableOrdered1"},
    {87, "UserReliableOrdered1"},
    {88, "UserReliableOrdered1"},
    {89, "UserReliableOrdered1"},
    {90, "UserReliableOrdered1"},
    {91, "UserReliableOrdered1"},
    {92, "UserReliableOrdered1"},
    {93, "UserReliableOrdered1"},
    {94, "UserReliableOrdered1"},
    {95, "UserReliableOrdered1"},
    {96, "UserReliableOrdered1"},
    {97, "UserReliableOrdered1"},
    {98, "UserReliableOrdered1"},

    {99, "Unused1"},
    {100, "Unused1"},
    {101, "Unused1"},
    {102, "Unused1"},
    {103, "Unused1"},
    {104, "Unused1"},
    {105, "Unused1"},
    {106, "Unused1"},
    {107, "Unused1"},
    {108, "Unused1"},
    {109, "Unused1"},
    {110, "Unused1"},
    {111, "Unused1"},
    {112, "Unused1"},
    {113, "Unused1"},
    {114, "Unused1"},
    {115, "Unused1"},
    {116, "Unused1"},
    {117, "Unused1"},
    {118, "Unused1"},
    {119, "Unused1"},
    {120, "Unused1"},
    {121, "Unused1"},
    {122, "Unused1"},
    {123, "Unused1"},
    {124, "Unused1"},
    {125, "Unused1"},
    {126, "Unused1"},
    {127, "Unused1"},

    {128,  "LibraryError"},
    {129, "Ping"},
    {130, "Pong"},
    {131,  "Connect"},
    {132, "ConnectResponse"},
    {133,  "ConnectionEstablished"},
    {134,  "Acknowledge"},
    {135,  "Disconnect"},
    {136, "Discovery"},
    {137,  "DiscoveryResponse"},
    {138,  "NatPunchMessage"},
    {139, "NatIntroductio"},
    {142,  "NatIntroductionConfirmRequest"},
    {143,  "NatIntroductionConfirmed"},
    {140,  "ExpantMTURequest"},
    {141,  "ExpandMTUSuccess"},
    
    {0, NULL}
};



static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 func_code;
    gint offset = 0;
    proto_tree *foo_hdr_tree, *foo_tree;

    func_code = tvb_get_guint8(tvb, offset);
    if (try_val_to_str(func_code, lidgren_func_vals) == NULL)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lidgren");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_str(pinfo->cinfo,COL_INFO, val_to_str(func_code, lidgren_func_vals, "Unknown function (%d)"));

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    foo_tree = proto_item_add_subtree(ti, ett_foo);

    /* Create header subtree */
    foo_hdr_tree = proto_tree_add_subtree(foo_tree, tvb, 0, 4, ett_hdr_foo, NULL, "Header");

    proto_tree_add_item(foo_hdr_tree, hf_foo_function_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_hdr_tree, hf_foo_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    
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
            VALS(lidgren_func_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_foo_sequence,
            { "Message Sequence Number", "foo.sequence",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0xFFFE,
            NULL, HFILL }
        },
        { &hf_foo_fragment_flag,
            { "Fragment Flag", "foo.fragmentflag",
            FT_UINT16, BASE_DEC,
            NULL, 0x1,
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

    foo_udp_handle = register_dissector("lidgren", dissect_foo, proto_foo);
}

static gboolean
test_foo(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    if ( tvb_get_guint8(tvb, offset) != 0x83 )
        return FALSE;
    
    if ( tvb_get_guint8(tvb, offset+1) != 0x00 )
        return FALSE;

    if ( tvb_get_guint8(tvb, offset+2) != 0x00 )
        return FALSE;
    
    /* Assume it's your packet */
    return TRUE;
}

static int
dissect_foo_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 func_code;
    gint offset = 0;
    proto_tree *foo_hdr_tree, *foo_tree;

    func_code = tvb_get_guint8(tvb, offset);
    if (try_val_to_str(func_code, lidgren_func_vals) == NULL)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lidgren");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_str(pinfo->cinfo,COL_INFO, val_to_str(func_code, lidgren_func_vals, "Unknown function (%d)"));

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    foo_tree = proto_item_add_subtree(ti, ett_foo);

    /* Create header subtree */
    foo_hdr_tree = proto_tree_add_subtree(foo_tree, tvb, 0, 4, ett_hdr_foo, NULL, "Header");

    proto_tree_add_item(foo_hdr_tree, hf_foo_function_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_hdr_tree, hf_foo_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    
    proto_tree_add_item(foo_hdr_tree, hf_foo_fragment_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_hdr_tree, hf_foo_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return tvb_reported_length(tvb);
}

static guint
get_foo_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)tvb_get_ntohl(tvb, offset+5);
}

static int
dissect_foo_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    udp_dissect_pdus(tvb, pinfo, tree, FRAME_HEADER_LEN, test_foo,
                     get_foo_len, dissect_foo_pdu, data);
    return tvb_reported_length(tvb);
}

static gboolean
dissect_foo_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_foo(pinfo, tvb, 0, data))
        return FALSE;

    /* specify that dissect_PROTOABBREV is to be called directly from now on for
     * packets for this "connection" ... but only do this if your heuristic sits directly
     * on top of (was called by) a dissector which established a conversation for the
     * protocol "port type". In other words: only directly over TCP, UDP, DCCP, ...
     * otherwise you'll be overriding the dissector that called your heuristic dissector.
     */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, foo_udp_handle);

    //dissect_foo(tvb, pinfo, tree, data);
    //return TRUE;
    return (udp_dissect_pdus(tvb, pinfo, tree, FRAME_HEADER_LEN, test_foo,
                     get_foo_len, dissect_foo_pdu, data) != 0);
}

void
proto_reg_handoff_foo(void)
{
    //static dissector_handle_t foo_handle;
    //foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    
    //Koden pa raden nedan ska kanske kommenteras bort?
    //dissector_add_uint("udp.port", FOO_PORT, foo_handle);

    //New code
    //foo_udp_handle = create_dissector_handle(dissect_foo_udp, proto_foo);

    foo_pdu_handle = create_dissector_handle(dissect_foo_pdu, proto_foo);

    //New code
    heur_dissector_add("udp", dissect_foo_heur_udp, "Lidgren over UDP",
                       "lidgren_udp", proto_foo, HEURISTIC_ENABLE);
        
//#ifdef OPTIONAL
    /* It's possible to write a dissector to be a dual heuristic/normal dissector */
    /*  by also registering the dissector "normally".                             */
    dissector_add_uint("udp", IP_PROTO_foo, foo_pdu_handle);
//#endif
}
