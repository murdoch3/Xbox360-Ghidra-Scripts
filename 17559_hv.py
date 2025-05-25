# Labels the 17559 Xbox 360 hypervisor
# Based on https:raw.githubusercontent.com/g91/XBLS/refs/heads/master/IDC/17559_hv.idc
# Note: the above resource seems to have the wrong syscall -> Hvx functions for
# 17559.  Seem to be the versions for 17489 instead.
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

# TODO: This code doesn't find the implementations of the functions from the
# jump tables.
# TODO: createFunction at locations with functions that Ghidra hasn't
# recognized.

from ghidra.program.model.data import DWordDataType
from ghidra.program.model.listing import Listing

hv_syscalls = {
    0: 	"HvxGetVersion",
    1: 	"HvxStartupProcessors",
    2: 	"HvxQuiesceProcessor",
    3: 	"HvxFlushEntireTb",
    4: 	"HvxFlushSingleTb",
    5: 	"HvxRelocateAndFlush",
    6: 	"HvxGetSpecialPurposeRegister",
    7: 	"HvxSetSpecialPurposeRegister",
    8: 	"HvxGetSocRegister",
    9: 	"HvxSetSocRegister",
    10: 	"HvxSetTimebaseToZero",
    11: 	"HvxZeroPage",
    12: 	"HvxFlushDcacheRange",
    13: 	"HvxPostOutput",
    14: 	"HvxEnablePPUPerformanceMonitor",
    15: 	"HvxGetImagePageTableEntry",
    16: 	"HvxSetImagePageTableEntr",
    17: 	"HvxCreateImageMapping",
    18: 	"HvxMapImagePage",
    19: 	"HvxCompleteImageMapping",
    20: 	"HvxLoadImageData",
    21: 	"HvxFinishImageDataLoad",
    22: 	"HvxStartResolveImports",
    23: 	"HvxResolveImports",
    24: 	"HvxXexUnk24",
    25: 	"HvxXexUnk25",
    26: 	"HvxFinishImageLoad",
    27: 	"HvxAbandonImageLoad",
    28: 	"HvxUnmapImagePages",
    29: 	"HvxUnmapImage",
    30: 	"HvxUnmapImageRange",
    31: 	"HvxCreateUserMode",
    32: 	"HvxDeleteUserMode",
    33: 	"HvxFlushUserModeTb",
    34: 	"HvxSetPowerMode",
    35: 	"HvxShadowBoot",
    36: 	"HvxBlowFuses",
    37: 	"HvxFsbInterrupt",
    38: 	"HvxLockL2",
    39: 	"HvxDvdAuthBuildNVPage",
    40: 	"HvxDvdAuthVerifyNVPage",
    41: 	"HvxDvdAuthRecordAuthenticationPage",
    42: 	"HvxDvdAuthRecordXControl",
    43: 	"HvxDvdAuthGetAuthPage",
    44: 	"HvxDvdAuthVerifyAuthPage",
    45: 	"HvxDvdAuthGetNextLBAIndex",
    46: 	"HvxDvdAuthVerifyLBA",
    47: 	"HvxDvdAuthClearDiscAuthInfo",
    48: 	"HvxKeysInitialize",
    49: 	"HvxKeysGetKeyProperties",
    50: 	"HvxKeysGetStatus",
    51: 	"HvxKeysGenerateRandomKey",
    52: 	"HvxKeysGetFactoryChallenge",
    53: 	"HvxKeysSetFactoryResponse",
    54: 	"HvxKeysSaveBootLoader",
    55: 	"HvxKeysSaveKeyVault",
    56: 	"HvxKeysSetKey",
    57: 	"HvxKeysGetKey",
    58: 	"HvxKeysGetDigest",
    59: 	"HvxKeysRsaPrvCrypt",
    60: 	"HvxKeysHmacSha",
    61: 	"HvxKeysAesCbc",
    62: 	"HvxKeysDes2Cbc",
    63: 	"HvxKeysDesCbc",
    64: 	"HvxKeysObscureKey",
    65: 	"HvxKeysSaveSystemUpdate",
    66: 	"HvxKeysExecute",
    67: 	"HvxDvdAuthTestMode",
    68: 	"HvxEnableTimebase",
    69: 	"HvxHdcpCalculateMi",
    70: 	"HvxHdcpCalculateAKsvSignature",
    71: 	"HvxHdcpCalculateBKsvSignature",
    72: 	"HvxSetRevocationList",
    73: 	"HvxEncryptedAllocationReserve",
    74: 	"HvxEncryptedAllocationMap",
    75: 	"HvxEncryptedAllocationUnmap",
    76: 	"HvxEncryptedAllocationRelease",
    77: 	"HvxEncryptedSweepAddressRange",
    78: 	"HvxKeysExCreateKeyVault",
    79: 	"HvxKeysExLoadKeyVault",
    80: 	"HvxKeysExSaveKeyVault",
    81: 	"HvxKeysExSetKey",
    82: 	"HvxKeysExGetKey",
    83: 	"HvxGetUpdateSequence",
    84: 	"HvxSecurityInitialize",
    85: 	"HvxSecurityLoadSettings",
    86: 	"HvxSecuritySaveSettings",
    87: 	"HvxSecuritySetDetected",
    88: 	"HvxSecurityGetDetected",
    89: 	"HvxSecuritySetActivated",
    90: 	"HvxSecurityGetActivated",
    91: 	"HvxSecuritySetStat",
    92: 	"HvxGetProtectedFlags",
    93: 	"HvxSetProtectedFlag",
    94: 	"HvxDvdAuthGetAuthResults",
    95: 	"HvxDvdAuthSetDriveAuthResult",
    96: 	"HvxDvdAuthSetDiscAuthResult",
    97: 	"HvxImageTransformImageKey",
    98: 	"HvxImageXexHeader",
    99: 	"HvxRevokeLoad",
    100: 	"HvxRevokeSave",
    101: 	"HvxRevokeUpdate",
    102: 	"HvxDvdAuthGetMediaId",
    103: 	"HvxXexActivationGetNonce",
    104: 	"HvxXexActivationSetLicense",
    105: 	"HvxXexActivationVerifyOwnership",
    106: 	"HvxIptvSetBoundaryKey",
    107: 	"HvxIptvSetSessionKey",
    108: 	"HvxIptvVerifyOmac1Signature",
    109: 	"HvxIptvGetAesCtrTransform",
    110: 	"HvxIptvGetSessionKeyHash",
    111: 	"HvxImageDvdEmulationMode",
    112: 	"HvxImageUserMode",
    113: 	"HvxImageShim",
    114: 	"HvxExpansionInstall",
    115: 	"HvxExpansionCall",
    116: 	"HvxDvdAuthFwcr",
    117: 	"HvxDvdAuthFcrt",
    118: 	"HvxDvdAuthEx",
    119: 	"HvxTest"
}

def get_syscall_name(id):
    if id in hv_syscalls:
        return hv_syscalls[id]
    else: return "HvxSyscall_" + str(id)

def resolve_jump_table_sc(sc_offset):
    """Finds the final function address given an offset into the syscall jump table
    
    Keyword arguments:
    sc_offset -- offset taken from the syscall table
    Return: resolved address, None if error
    """
    if not getShort(toAddr(sc_offset)) == 0x3960 or not getShort(toAddr(sc_offset+4)) == 0x4BFF:
        print("{} isn't in the jump table".format(hex(sc_offset)))
        return None
    
    # Addresses into a function table?
    start = getInt(toAddr(0x80))    # from 0x77c
    offset = getShort(toAddr(sc_offset+2))
    func_addr = getInt(toAddr(start + offset))
    return func_addr
    

def label_hv_syscalls():
    """
    Uses the syscall table to find and label HV functions.
    """
    
    _v_sc = toAddr("0xc00")
    sc_handler = toAddr("0xb04")
    sc_table = toAddr("0x15fd0")
    sc_count = 0x78 # 120 syscalls, from 0xb04

    # Name the system call handlers and table
    createLabel(_v_sc, "_v_SYSTEM_CALL", True)
    createLabel(sc_handler, "_syscallHandler", True)
    createLabel(sc_table, "_SyscallTable", True)

    for i in range(sc_count):
        sc_name = get_syscall_name(i)
        table_offset = (0x15fd0+4*i)
        table_addr = toAddr(table_offset)
        createData(table_addr, DWordDataType())
        sc_offset = getInt(table_addr)
        #print("Handling syscall {} - {}".format(i, sc_name))
        #print("Offset: {}".format(hex(sc_offset)))

        # Handle sc_offset.  Can be disabled, in a jump table, or a function.
        if getInt(toAddr(sc_offset)) == 0x38600000 and getInt(toAddr(sc_offset + 4)) == 0x4E800020:
            print("{} (disabled)".format(sc_name))
            setPreComment(table_addr, "{} (disabled)".format(sc_name))
        elif getShort(toAddr(sc_offset)) == 0x3960 and getShort(toAddr(sc_offset+4)) == 0x4BFF:
            print("{} - sc_offset: {} (jump table)".format(sc_name, sc_offset))
            setPreComment(toAddr(sc_offset), sc_name)
            func_addr = resolve_jump_table_sc(sc_offset)
            print("{} at {}".format(sc_name, hex(func_addr)))
            createLabel(toAddr(func_addr), sc_name, True)
        else:
            print("{} (function)".format(sc_name))
            #createFunction(sc_offset, null)
            createLabel(toAddr(sc_offset), sc_name, True)

memory = currentProgram.getMemory()
label_hv_syscalls()
