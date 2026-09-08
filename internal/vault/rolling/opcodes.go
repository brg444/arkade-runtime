package rolling

// Bytecode dialect pinned to arkade-os/emulator 4feb9eaa81b49f8d321407e92dba107ec9ba5158.
// Keep the legacy Savings interpreter dependency unchanged. The isolated
// qualification module executes this compiler against the pinned upstream VM.
const (
	OP_MERKLEBRANCHVERIFY        = 0xb3
	OP_TXWEIGHT                  = 0xd6
	OP_MUL                       = 0x95
	OP_0NOTEQUAL                 = 0x92
	OP_1ADD                      = 0x8b
	OP_1SUB                      = 0x8c
	OP_ADD                       = 0x93
	OP_BIN2NUM                   = 0xd8
	OP_CAT                       = 0x7e
	OP_CHECKSIGFROMSTACK         = 0xcc
	OP_CHECKTIMEVERIFY           = 0xdc
	OP_DEPTH                     = 0x74
	OP_DIV                       = 0x96
	OP_DROP                      = 0x75
	OP_DUP                       = 0x76
	OP_ELSE                      = 0x67
	OP_ENDIF                     = 0x68
	OP_EQUAL                     = 0x87
	OP_EQUALVERIFY               = 0x88
	OP_FROMALTSTACK              = 0x6c
	OP_GREATERTHAN               = 0xa0
	OP_GREATERTHANOREQUAL        = 0xa2
	OP_IF                        = 0x63
	OP_INSPECTASSETGROUP         = 0xeb
	OP_INSPECTASSETGROUPASSETID  = 0xe6
	OP_INSPECTASSETGROUPNUM      = 0xea
	OP_INSPECTINPUTOUTPOINT      = 0xc7
	OP_INSPECTINPUTPACKET        = 0xf5
	OP_INSPECTINPUTSCRIPTPUBKEY  = 0xca
	OP_INSPECTINPUTVALUE         = 0xc9
	OP_INSPECTINTENTMESSAGE      = 0xf8
	OP_INSPECTLOCKTIME           = 0xd3
	OP_INSPECTNUMASSETGROUPS     = 0xe5
	OP_INSPECTNUMINPUTS          = 0xd4
	OP_INSPECTNUMOUTPUTS         = 0xd5
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_INSPECTPACKET             = 0xf4
	OP_INSPECTVERSION            = 0xd2
	OP_LEFT                      = 0x80
	OP_LESSTHAN                  = 0x9f
	OP_LESSTHANOREQUAL           = 0xa1
	OP_MOD                       = 0x97
	OP_NOT                       = 0x91
	OP_NUM2BIN                   = 0xd7
	OP_PICK                      = 0x79
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
	OP_PUSHEXPIRY                = 0xdb
	OP_RIGHT                     = 0x81
	OP_ROT                       = 0x7b
	OP_SHA256                    = 0xa8
	OP_SIZE                      = 0x82
	OP_SUB                       = 0x94
	OP_SWAP                      = 0x7c
	OP_TOALTSTACK                = 0x6b
	OP_TRUE                      = 0x51
	OP_TUNNEL                    = 0xf7
	OP_VERIFY                    = 0x69
)
