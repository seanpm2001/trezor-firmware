# Automatically generated by pb2py
# fmt: off
# isort:skip_file

from trezor import utils

Initialize = 0
Ping = 1
Success = 2
Failure = 3
ChangePin = 4
WipeDevice = 5
GetEntropy = 9
Entropy = 10
LoadDevice = 13
ResetDevice = 14
SetBusy = 16
Features = 17
PinMatrixRequest = 18
PinMatrixAck = 19
Cancel = 20
LockDevice = 24
ApplySettings = 25
ButtonRequest = 26
ButtonAck = 27
ApplyFlags = 28
GetNonce = 31
Nonce = 33
BackupDevice = 34
EntropyRequest = 35
EntropyAck = 36
PassphraseRequest = 41
PassphraseAck = 42
RecoveryDevice = 45
WordRequest = 46
WordAck = 47
GetFeatures = 55
SdProtect = 79
ChangeWipeCode = 82
EndSession = 83
DoPreauthorized = 84
PreauthorizedRequest = 85
CancelAuthorization = 86
RebootToBootloader = 87
GetFirmwareHash = 88
FirmwareHash = 89
UnlockPath = 93
UnlockedPathRequest = 94
ShowDeviceTutorial = 95
FirmwareErase = 6
FirmwareUpload = 7
FirmwareRequest = 8
SelfTest = 32
GetPublicKey = 11
PublicKey = 12
SignTx = 15
TxRequest = 21
TxAck = 22
GetAddress = 29
Address = 30
SignMessage = 38
VerifyMessage = 39
MessageSignature = 40
GetOwnershipId = 43
OwnershipId = 44
GetOwnershipProof = 49
OwnershipProof = 50
AuthorizeCoinJoin = 51
CipherKeyValue = 23
CipheredKeyValue = 48
SignIdentity = 53
SignedIdentity = 54
GetECDHSessionKey = 61
ECDHSessionKey = 62
CosiCommit = 71
CosiCommitment = 72
CosiSign = 73
CosiSignature = 74
DebugLinkDecision = 100
DebugLinkGetState = 101
DebugLinkState = 102
DebugLinkStop = 103
DebugLinkLog = 104
DebugLinkMemoryRead = 110
DebugLinkMemory = 111
DebugLinkMemoryWrite = 112
DebugLinkFlashErase = 113
DebugLinkLayout = 9001
DebugLinkReseedRandom = 9002
DebugLinkRecordScreen = 9003
DebugLinkEraseSdCard = 9005
DebugLinkWatchLayout = 9006
DebugLinkResetDebugEvents = 9007
if not utils.BITCOIN_ONLY:
    SetU2FCounter = 63
    GetNextU2FCounter = 80
    NextU2FCounter = 81
    TxAckPaymentRequest = 37
    EthereumGetPublicKey = 450
    EthereumPublicKey = 451
    EthereumGetAddress = 56
    EthereumAddress = 57
    EthereumSignTx = 58
    EthereumSignTxEIP1559 = 452
    EthereumTxRequest = 59
    EthereumTxAck = 60
    EthereumSignMessage = 64
    EthereumVerifyMessage = 65
    EthereumMessageSignature = 66
    EthereumSignTypedData = 464
    EthereumTypedDataStructRequest = 465
    EthereumTypedDataStructAck = 466
    EthereumTypedDataValueRequest = 467
    EthereumTypedDataValueAck = 468
    EthereumTypedDataSignature = 469
    EthereumSignTypedHash = 470
    NEMGetAddress = 67
    NEMAddress = 68
    NEMSignTx = 69
    NEMSignedTx = 70
    NEMDecryptMessage = 75
    NEMDecryptedMessage = 76
    TezosGetAddress = 150
    TezosAddress = 151
    TezosSignTx = 152
    TezosSignedTx = 153
    TezosGetPublicKey = 154
    TezosPublicKey = 155
    StellarSignTx = 202
    StellarTxOpRequest = 203
    StellarGetAddress = 207
    StellarAddress = 208
    StellarCreateAccountOp = 210
    StellarPaymentOp = 211
    StellarPathPaymentStrictReceiveOp = 212
    StellarManageSellOfferOp = 213
    StellarCreatePassiveSellOfferOp = 214
    StellarSetOptionsOp = 215
    StellarChangeTrustOp = 216
    StellarAllowTrustOp = 217
    StellarAccountMergeOp = 218
    StellarManageDataOp = 220
    StellarBumpSequenceOp = 221
    StellarManageBuyOfferOp = 222
    StellarPathPaymentStrictSendOp = 223
    StellarSignedTx = 230
    CardanoGetPublicKey = 305
    CardanoPublicKey = 306
    CardanoGetAddress = 307
    CardanoAddress = 308
    CardanoTxItemAck = 313
    CardanoTxAuxiliaryDataSupplement = 314
    CardanoTxWitnessRequest = 315
    CardanoTxWitnessResponse = 316
    CardanoTxHostAck = 317
    CardanoTxBodyHash = 318
    CardanoSignTxFinished = 319
    CardanoSignTxInit = 320
    CardanoTxInput = 321
    CardanoTxOutput = 322
    CardanoAssetGroup = 323
    CardanoToken = 324
    CardanoTxCertificate = 325
    CardanoTxWithdrawal = 326
    CardanoTxAuxiliaryData = 327
    CardanoPoolOwner = 328
    CardanoPoolRelayParameters = 329
    CardanoGetNativeScriptHash = 330
    CardanoNativeScriptHash = 331
    CardanoTxMint = 332
    CardanoTxCollateralInput = 333
    CardanoTxRequiredSigner = 334
    CardanoTxInlineDatumChunk = 335
    CardanoTxReferenceScriptChunk = 336
    CardanoTxReferenceInput = 337
    RippleGetAddress = 400
    RippleAddress = 401
    RippleSignTx = 402
    RippleSignedTx = 403
    MoneroTransactionInitRequest = 501
    MoneroTransactionInitAck = 502
    MoneroTransactionSetInputRequest = 503
    MoneroTransactionSetInputAck = 504
    MoneroTransactionInputViniRequest = 507
    MoneroTransactionInputViniAck = 508
    MoneroTransactionAllInputsSetRequest = 509
    MoneroTransactionAllInputsSetAck = 510
    MoneroTransactionSetOutputRequest = 511
    MoneroTransactionSetOutputAck = 512
    MoneroTransactionAllOutSetRequest = 513
    MoneroTransactionAllOutSetAck = 514
    MoneroTransactionSignInputRequest = 515
    MoneroTransactionSignInputAck = 516
    MoneroTransactionFinalRequest = 517
    MoneroTransactionFinalAck = 518
    MoneroKeyImageExportInitRequest = 530
    MoneroKeyImageExportInitAck = 531
    MoneroKeyImageSyncStepRequest = 532
    MoneroKeyImageSyncStepAck = 533
    MoneroKeyImageSyncFinalRequest = 534
    MoneroKeyImageSyncFinalAck = 535
    MoneroGetAddress = 540
    MoneroAddress = 541
    MoneroGetWatchKey = 542
    MoneroWatchKey = 543
    DebugMoneroDiagRequest = 546
    DebugMoneroDiagAck = 547
    MoneroGetTxKeyRequest = 550
    MoneroGetTxKeyAck = 551
    MoneroLiveRefreshStartRequest = 552
    MoneroLiveRefreshStartAck = 553
    MoneroLiveRefreshStepRequest = 554
    MoneroLiveRefreshStepAck = 555
    MoneroLiveRefreshFinalRequest = 556
    MoneroLiveRefreshFinalAck = 557
    EosGetPublicKey = 600
    EosPublicKey = 601
    EosSignTx = 602
    EosTxActionRequest = 603
    EosTxActionAck = 604
    EosSignedTx = 605
    BinanceGetAddress = 700
    BinanceAddress = 701
    BinanceGetPublicKey = 702
    BinancePublicKey = 703
    BinanceSignTx = 704
    BinanceTxRequest = 705
    BinanceTransferMsg = 706
    BinanceOrderMsg = 707
    BinanceCancelMsg = 708
    BinanceSignedTx = 709
    WebAuthnListResidentCredentials = 800
    WebAuthnCredentials = 801
    WebAuthnAddResidentCredential = 802
    WebAuthnRemoveResidentCredential = 803
    SolanaGetPublicKey = 900
    SolanaPublicKey = 901
    SolanaGetAddress = 902
    SolanaAddress = 903
