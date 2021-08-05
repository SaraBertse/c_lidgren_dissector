#include <epan/dissectors/packet-udp.h> //This "carries" the program

#define FRAME_HEADER_LEN 5
#define IP_PROTO_lidgren 254

static int proto_lidgren = -1;
static int hf_lidgren_function_code = -1;
static int hf_lidgren_sequence = -1;
static int hf_lidgren_fragment_flag = -1;
static int hf_lidgren_payload_length = -1;
static int hf_lidgren_payload_field = -1;
static gint ett_lidgren = -1;
static gint ett_hdr_lidgren = -1;
static dissector_handle_t lidgren_pdu_handle;
static dissector_handle_t lidgren_udp_handle;
static dissector_handle_t lidgren_tcp_handle;
conversation_t *conversation;


const value_string lidgren_func_vals[] = {
    {0, "Unconnected"},
    {1, "userUnreliable"},
    {2, "UserSequenced1"},
    {3, "UserSequenced2"},
    {4, "UserSequenced3"},
    {5, "UserSequenced4"},
    {6, "UserSequenced5"},
    {7, "UserSequenced6"},
    {8, "UserSequenced7"},
    {9, "UserSequenced8"},
    {10, "UserSequenced9"},
    {11, "UserSequenced10"},
    {12, "UserSequenced11"},
    {13, "UserSequenced12"},
    {14, "UserSequenced13"},
    {15, "UserSequenced14"},
    {16, "UserSequenced15"},
    {17, "UserSequenced16"},
    {18, "UserSequenced17"},
    {19, "UserSequenced18"},
    {20, "UserSequenced19"},
    {21, "UserSequenced20"},
    {22, "UserSequenced21"},
    {23, "UserSequenced22"},
    {24, "UserSequenced23"},
    {25, "UserSequenced24"},
    {26, "UserSequenced25"},
    {27, "UserSequenced26"},
    {28, "UserSequenced27"},
    {29, "UserSequenced28"},
    {30, "UserSequenced29"},
    {31, "UserSequenced30"},
    {32, "UserSequenced31"},
    {33, "UserSequenced32"},

    {34, "UserRealiableUnordered"},

    {35, "UserRealiableSequenced1"},
    {36, "UserRealiableSequenced2"},
    {37, "UserRealiableSequenced3"},
    {38, "UserRealiableSequenced4"},
    {39, "UserRealiableSequenced5"},
    {40, "UserRealiableSequenced6"},
    {41, "UserRealiableSequenced7"},
    {42, "UserRealiableSequenced8"},
    {43, "UserRealiableSequenced9"},
    {44, "UserRealiableSequenced10"},
    {45, "UserRealiableSequenced11"},
    {46, "UserRealiableSequenced12"},
    {47, "UserRealiableSequenced13"},
    {48, "UserRealiableSequenced14"},
    {49, "UserRealiableSequenced15"},
    {50, "UserRealiableSequenced16"},
    {51, "UserRealiableSequenced17"},
    {52, "UserRealiableSequenced18"},
    {53, "UserRealiableSequenced19"},
    {54, "UserRealiableSequenced20"},
    {55, "UserRealiableSequenced21"},
    {56, "UserRealiableSequenced22"},
    {57, "UserRealiableSequenced23"},
    {58, "UserRealiableSequenced24"},
    {59, "UserRealiableSequenced25"},
    {60, "UserRealiableSequenced26"},
    {61, "UserRealiableSequenced27"},
    {62, "UserRealiableSequenced28"},
    {63, "UserRealiableSequenced29"},
    {64, "UserRealiableSequenced30"},
    {65, "UserRealiableSequenced31"},
    {66, "UserRealiableSequenced32"},

    {67, "UserReliableOrdered1"},
    {68, "UserReliableOrdered2"},
    {69, "UserReliableOrdered3"},
    {70, "UserReliableOrdered4"},
    {71, "UserReliableOrdered5"},
    {72, "UserReliableOrdered6"},
    {73, "UserReliableOrdered7"},
    {74, "UserReliableOrdered8"},
    {75, "UserReliableOrdered9"},
    {76, "UserReliableOrdered10"},
    {77, "UserReliableOrdered11"},
    {78, "UserReliableOrdered12"},
    {79, "UserReliableOrdered13"},
    {80, "UserReliableOrdered14"},
    {81, "UserReliableOrdered15"},
    {82, "UserReliableOrdered16"},
    {83, "UserReliableOrdered17"},
    {84, "UserReliableOrdered18"},
    {85, "UserReliableOrdered19"},
    {86, "UserReliableOrdered20"},
    {87, "UserReliableOrdered21"},
    {88, "UserReliableOrdered22"},
    {89, "UserReliableOrdered23"},
    {90, "UserReliableOrdered24"},
    {91, "UserReliableOrdered25"},
    {92, "UserReliableOrdered26"},
    {93, "UserReliableOrdered27"},
    {94, "UserReliableOrdered28"},
    {95, "UserReliableOrdered29"},
    {96, "UserReliableOrdered30"},
    {97, "UserReliableOrdered31"},
    {98, "UserReliableOrdered32"},

    {99, "Unused1"},
    {100, "Unused2"},
    {101, "Unused3"},
    {102, "Unused4"},
    {103, "Unused5"},
    {104, "Unused6"},
    {105, "Unused7"},
    {106, "Unused8"},
    {107, "Unused9"},
    {108, "Unused10"},
    {109, "Unused11"},
    {110, "Unused12"},
    {111, "Unused13"},
    {112, "Unused14"},
    {113, "Unused15"},
    {114, "Unused16"},
    {115, "Unused17"},
    {116, "Unused18"},
    {117, "Unused19"},
    {118, "Unused20"},
    {119, "Unused21"},
    {120, "Unused22"},
    {121, "Unused23"},
    {122, "Unused24"},
    {123, "Unused25"},
    {124, "Unused26"},
    {125, "Unused27"},
    {126, "Unused28"},
    {127, "Unused29"},

    {128, "LibraryError"},
    {129, "Ping"},
    {130, "Pong"},
    {131, "Connect"},
    {132, "ConnectResponse"},
    {133, "ConnectionEstablished"},
    {134, "Acknowledge"},
    {135, "Disconnect"},
    {136, "Discovery"},
    {137, "DiscoveryResponse"},
    {138, "NatPunchMessage"},
    {139, "NatIntroductio"},
    {142, "NatIntroductionConfirmRequest"},
    {143, "NatIntroductionConfirmed"},
    {140, "ExpantMTURequest"},
    {141, "ExpandMTUSuccess"},
    
    {0, NULL}
};


//The main dissecting function for the non-heuristic part of the dissector
static int
dissect_lidgren(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 func_code;
    guint16 length;
    gint offset = 0;
    proto_tree *lidgren_hdr_tree, *lidgren_tree;
    length = tvb_get_letohs(tvb, offset+3);
    func_code = tvb_get_guint8(tvb, offset);
    
    if (try_val_to_str(func_code, lidgren_func_vals) == NULL)
        return 0;

    //Updates/sets the Wireshark columns "Protocol" and "Info" 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lidgren");
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_str(pinfo->cinfo,COL_INFO, val_to_str(func_code, lidgren_func_vals, "Unknown function (%d)"));

    proto_item *ti = proto_tree_add_item(tree, proto_lidgren, tvb, 0, -1, ENC_NA);

    //Creates Lidgren tree
    lidgren_tree = proto_item_add_subtree(ti, ett_lidgren);

    //Creates Lidgren "Header" subtree
    lidgren_hdr_tree = proto_tree_add_subtree(lidgren_tree, tvb, 0, 4, ett_hdr_lidgren, NULL, "Header");

    //Adds fields to the "Header" subtree
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_function_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_fragment_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    //Adds the "Payload" field to the Lidgren tree
    proto_tree_add_item(lidgren_tree, hf_lidgren_payload_field, tvb, offset, (length/8), ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

//Registers the dissector and defines the header fields
void
proto_register_lidgren(void)
{
    static hf_register_info hf[] = {
        { &hf_lidgren_function_code,
            { "Function", "lidgren.function",
            FT_UINT8, BASE_DEC,
            VALS(lidgren_func_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_lidgren_sequence,
            { "Message Sequence Number", "lidgren.sequence",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0xFFFE,
            NULL, HFILL }
        },
        { &hf_lidgren_fragment_flag,
            { "Fragment Flag", "lidgren.fragmentflag",
            FT_UINT16, BASE_DEC,
            NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_lidgren_payload_length,
            { "Payload Length (in bits)", "lidgren.payloadlen",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lidgren_payload_field,
            { "Payload", "lidgren.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    //Sets up the protocol subtree array
    static gint *ett[] = {
        &ett_lidgren,
        &ett_hdr_lidgren
    };

    //Defines protocol names
    proto_lidgren = proto_register_protocol (
        "Lidgren Protocol", /* name        */
        "Lidgren",          /* short name  */
        "lidgren"           /* filter_name */
        );

    proto_register_field_array(proto_lidgren, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lidgren_udp_handle = register_dissector("lidgren", dissect_lidgren, proto_lidgren);
}

//Checks whether the packet is Lidgren. Returns TRUE if the packet is Lidgren
static gboolean
test_lidgren(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    if ( tvb_get_guint8(tvb, offset) != 0x83 )
        return FALSE;
    
    if ( tvb_get_guint8(tvb, offset+1) != 0x00 )
        return FALSE;

    if ( tvb_get_guint8(tvb, offset+2) != 0x00 )
        return FALSE;

    return TRUE;
}

//The dissector for the heuristic part of the dissector
static int
dissect_lidgren_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 func_code;
    guint16 length;
    gint offset = 0;
    proto_tree *lidgren_hdr_tree, *lidgren_tree;
    length = tvb_get_letohs(tvb, offset+3);
    func_code = tvb_get_guint8(tvb, offset);

    if (try_val_to_str(func_code, lidgren_func_vals) == NULL)
        return 0;

    //Updates/sets the Wireshark columns "Protocol" and "Info" 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lidgren");
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_str(pinfo->cinfo,COL_INFO, val_to_str(func_code, lidgren_func_vals, "Unknown function (%d)"));

    proto_item *ti = proto_tree_add_item(tree, proto_lidgren, tvb, 0, -1, ENC_NA);

    //Creates Lidgren tree
    lidgren_tree = proto_item_add_subtree(ti, ett_lidgren);

    //Creates Lidgren "Header" subtree
    lidgren_hdr_tree = proto_tree_add_subtree(lidgren_tree, tvb, 0, 4, ett_hdr_lidgren, NULL, "Header");

    //Adds fields to the "Header" subtree
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_function_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_fragment_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(lidgren_hdr_tree, hf_lidgren_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    //Adds the "Payload" field to the Lidgren tree
    proto_tree_add_item(lidgren_tree, hf_lidgren_payload_field, tvb, offset, (length/8), ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

//Returns the value of the length flag for the packet
static guint
get_lidgren_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_letohs(tvb, offset+3);
}

//Returns the length of the packet
static int
dissect_lidgren_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    udp_dissect_pdus(tvb, pinfo, tree, FRAME_HEADER_LEN, test_lidgren,
                     get_lidgren_len, dissect_lidgren_pdu, data);
    return tvb_reported_length(tvb);
}

//Returns TRUE if packet is Lidgren, otherwise FALSE
static gboolean
dissect_lidgren_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_lidgren(pinfo, tvb, 0, data))
        return FALSE;

    /*If the protocol is Lidgren, the non-heuristic part of the Lidgren dissector (dissect_lidgren) 
      should keep dissecting as long as it's within the same conversation */ 
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, lidgren_udp_handle);

    return (udp_dissect_pdus(tvb, pinfo, tree, FRAME_HEADER_LEN, test_lidgren,
                     get_lidgren_len, dissect_lidgren_pdu, data) != 0);
}

//Sets the dissector handles so that Wireshark can find them
void
proto_reg_handoff_lidgren(void)
{
    lidgren_pdu_handle = create_dissector_handle(dissect_lidgren_pdu, proto_lidgren);

    heur_dissector_add("udp", dissect_lidgren_heur_udp, "Lidgren over UDP",
                       "lidgren_udp", proto_lidgren, HEURISTIC_ENABLE);
        
    //Registers the non-heuristic dissector to use it with conversations
    dissector_add_uint("udp", IP_PROTO_lidgren, lidgren_pdu_handle);
}
