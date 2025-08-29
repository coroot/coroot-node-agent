
#define FDB_RECRUITSTORAGEREQUEST 905920
#define FDB_COMMITTRANSACTIONREQUEST 93948
#define FDB_GETREADVERSIONREQUEST 838566
#define FDB_OPENDATABASECOORDREQUEST 214728
#define FDB_GLOBALCONFIGREFRESHREQUEST 2828131
#define FDB_GETKEYSERVERLOCATIONSREQUEST 9144680
#define FDB_GETVALUEREQUEST 8454530
#define FDB_GETKEYVALUESREQUEST 6795746
#define FDB_GETKEYVALUESSTREAMREQUEST 6795746
#define FDB_CHANGEFEEDSTREAMREQUEST 6795746
#define FDB_GETMAPPEDKEYVALUESREQUEST 6795747
#define FDB_SETREQUEST 7554186
#define FDB_CLEARREQUEST 8500026
#define FDB_GETKEYREQUEST 10457870
#define FDB_WATCHVALUEREQUEST 14747733
#define FDB_INITIALIZESTORAGEREQUEST 16665642
#define FDB_INITIALIZEGRVPROXYREQUEST 8265613
#define FDB_INITIALIZECOMMITPROXYREQUEST 10344153
#define FDB_INITIALIZETLOGREQUEST 15604392
#define FDB_INITIALIZERATEKEEPERREQUEST 6416816
#define FDB_TLOGCOMMITREQUEST 4022206
#define FDB_TLOGPEEKREQUEST 11001131
#define FDB_TLOGPEEKSTREAMREQUEST 10072821
#define FDB_GETSTORAGEMETRICSREQUEST 13290999
#define FDB_GETSERVERDBINFOREQUEST 9467439
#define FDB_UPDATESERVERDBINFOREQUEST 9467438
#define FDB_REGISTERWORKERREQUEST 14332605
#define FDB_GETWORKERSREQUEST 1254174
#define FDB_STATUSREQUEST 14419140
#define FDB_PINGREQUEST 4707015
#define FDB_ECHOREQUEST 10624019
#define FDB_NETWORKTESTREQUEST 4146513
#define FDB_RECRUITBLOBWORKERREQUEST 72435
#define FDB_INITIALIZEBLOBWORKERREQUEST 5838547
#define FDB_INITIALIZEBLOBMANAGERREQUEST 2567474
#define FDB_HALTBLOBWORKERREQUEST 1985879
#define FDB_HALTBLOBMANAGERREQUEST 4149140
#define FDB_BLOBGRANULEFILEREQUEST 4150141
#define FDB_GETBLOBGRANULELOCATIONSREQUEST 2508597
#define FDB_ASSIGNBLOBRANGEREQUEST 905381
#define FDB_REVOKEBLOBRANGEREQUEST 4844288
#define FDB_INITIALIZEBLOBMIGRATORREQUEST 7932681
#define FDB_HALTBLOBMIGRATORREQUEST 4980139
#define FDB_INITIALIZEENCRYPTKEYPROXYREQUEST 4180191
#define FDB_HALTENCRYPTKEYPROXYREQUEST 2378138
#define FDB_CONFIGTRANSACTIONGETREQUEST 923040
#define FDB_CONFIGTRANSACTIONCOMMITREQUEST 103841
#define FDB_CONFIGFOLLOWERGETCHANGESREQUEST 178935
#define FDB_CONFIGBROADCASTCHANGESREQUEST 601281
#define FDB_INITIALIZECONSISTENCYSCANREQUEST 3104275
#define FDB_HALTCONSISTENCYSCANREQUEST 2323417

// Most common Reply FileIdentifiers
#define FDB_GETVALUEREPLY 1378929
#define FDB_GETKEYVALUESREPLY 1783066
#define FDB_GETKEYVALUESSTREAMREPLY 1783066
#define FDB_CHANGEFEEDSTREAMREPLY 1783066
#define FDB_GETMAPPEDKEYVALUESREPLY 1783067
#define FDB_GETKEYREPLY 11226513
#define FDB_GETREADVERSIONREPLY 15709388
#define FDB_TLOGCOMMITREPLY 3
#define FDB_TLOGPEEKREPLY 11365689
#define FDB_TLOGPEEKSTREAMREPLY 10072848
#define FDB_ACKNOWLEDGEMENTREPLY 1389929
#define FDB_VERSIONREPLY 3
#define FDB_CHECKREPLY 11
#define FDB_WATCHVALUEREPLY 3
#define FDB_GETSTORAGEMETRICSREPLY 15491478
#define FDB_INITIALIZESTORAGEREPLY 10390645
#define FDB_RECRUITSTORAGEREPLY 15877089
#define FDB_GETCOMMITVERSIONREPLY 3568822
#define FDB_GETSERVERDBINFOREPLY 9467439
#define FDB_STATUSREPLY 9980504
#define FDB_LOADEDREPLY 9956350
#define FDB_REGISTERWORKERREPLY 16475696
#define FDB_NETWORKTESTREPLY 14465374
#define FDB_ECHOSERVERINTERFACE 3152015
#define FDB_RECRUITBLOBWORKERREPLY 9908409
#define FDB_INITIALIZEBLOBWORKERREPLY 6095215
#define FDB_BLOBGRANULEFILEREPLY 6858612
#define FDB_GETBLOBGRANULELOCATIONSREPLY 2923309
#define FDB_MINBLOBVERSIONREPLY 6857512
#define FDB_GLOBALCONFIGREFRESHREPLY 12680327
#define FDB_GETKEYSERVERLOCATIONSREPLY 10636023
#define FDB_CONFIGTRANSACTIONGETREPLY 2034110
#define FDB_CONFIGTRANSACTIONGETGENERATIONREPLY 2934851
#define FDB_CONFIGFOLLOWERGETCHANGESREPLY 234859
#define FDB_CONFIGBROADCASTCHANGESREPLY 4014928
#define FDB_GETHEALTHMETRICSREPLY 11544290
#define FDB_SPLITMETRICSREPLY 11530792
#define FDB_PROTOCOLINFOREPLY 7784298
#define FDB_CHECKDESCRIPTORMUTABLEREPLY 7784299

// Key interface FileIdentifiers
#define FDB_STORAGESERVERINTERFACE 15302073
#define FDB_GRVPROXYINTERFACE 8743216
#define FDB_COMMITPROXYINTERFACE 8954922
#define FDB_MASTERINTERFACE 5979145
#define FDB_RATEKEEPERINTERFACE 5983305
#define FDB_DATADISTRIBUTORINTERFACE 12383874
#define FDB_TLOGINTERFACE 16308510
#define FDB_RESOLVERINTERFACE 1755944
#define FDB_BLOBWORKERINTERFACE 8358753
#define FDB_BLOBMANAGERINTERFACE 369169
#define FDB_ENCRYPTKEYPROXYINTERFACE 1303419
#define FDB_CONSISTENCYSCANINTERFACE 4983265
#define FDB_WORKERINTERFACE 14712718
#define FDB_CLUSTERINTERFACE 15888863
#define FDB_PROCESSINTERFACE 985636
#define FDB_CLIENTDBINFO 5355080
#define FDB_SERVERDBINFO 13838807
#define FDB_COMMITID 14254927
#define FDB_RANGERESULTREF 3985192
#define FDB_UNIQUEGENERATION 16684234
#define FDB_VOID 2010442

static inline __attribute__((__always_inline__))
int is_foundationdb_connect_packet(char *payload) {
    // FoundationDB ConnectPacket: [Length(4)][ProtocolVersion(8)][...]
    __u16 version_magic;
    if (bpf_probe_read(&version_magic, sizeof(version_magic), payload + 10) == 0) {
        // FoundationDB protocol versions contain 0x1FDB at offset 10-11
        if (version_magic == 0x1FDB) {
            return 1;
        }
    }
    return 0;
}


static inline __attribute__((__always_inline__))
int is_known_fdb_operation(__u32 file_id) {
    switch (file_id) {
    // Core request operations  
    case FDB_GETVALUEREQUEST:
    case FDB_GETKEYVALUESREQUEST:  // Also covers STREAM and CHANGEFEED variants (same ID 6795746)
    case FDB_GETMAPPEDKEYVALUESREQUEST:
    case FDB_COMMITTRANSACTIONREQUEST:
    case FDB_GETREADVERSIONREQUEST:
    case FDB_SETREQUEST:
    case FDB_CLEARREQUEST:
    case FDB_GETKEYREQUEST:
    case FDB_WATCHVALUEREQUEST:
    
    // Database coordination
    case FDB_OPENDATABASECOORDREQUEST:
    case FDB_GLOBALCONFIGREFRESHREQUEST:
    case FDB_GETKEYSERVERLOCATIONSREQUEST:
    case FDB_GETSERVERDBINFOREQUEST:
    case FDB_UPDATESERVERDBINFOREQUEST:
    
    // Worker and process management
    case FDB_REGISTERWORKERREQUEST:
    case FDB_GETWORKERSREQUEST:
    case FDB_RECRUITSTORAGEREQUEST:
    case FDB_INITIALIZESTORAGEREQUEST:
    case FDB_INITIALIZEGRVPROXYREQUEST:
    case FDB_INITIALIZECOMMITPROXYREQUEST:
    case FDB_INITIALIZETLOGREQUEST:
    case FDB_INITIALIZERATEKEEPERREQUEST:
    
    // Transaction log operations
    case FDB_TLOGCOMMITREQUEST:
    case FDB_TLOGPEEKREQUEST:
    case FDB_TLOGPEEKSTREAMREQUEST:
    
    // Storage operations
    case FDB_GETSTORAGEMETRICSREQUEST:
    
    // Network and monitoring
    case FDB_STATUSREQUEST:
    case FDB_PINGREQUEST:
    case FDB_ECHOREQUEST:
    case FDB_NETWORKTESTREQUEST:
    
    // Blob storage operations
    case FDB_RECRUITBLOBWORKERREQUEST:
    case FDB_INITIALIZEBLOBWORKERREQUEST:
    case FDB_INITIALIZEBLOBMANAGERREQUEST:
    case FDB_HALTBLOBWORKERREQUEST:
    case FDB_HALTBLOBMANAGERREQUEST:
    case FDB_BLOBGRANULEFILEREQUEST:
    case FDB_GETBLOBGRANULELOCATIONSREQUEST:
    case FDB_ASSIGNBLOBRANGEREQUEST:
    case FDB_REVOKEBLOBRANGEREQUEST:
    case FDB_INITIALIZEBLOBMIGRATORREQUEST:
    case FDB_HALTBLOBMIGRATORREQUEST:
    
    // Encryption operations
    case FDB_INITIALIZEENCRYPTKEYPROXYREQUEST:
    case FDB_HALTENCRYPTKEYPROXYREQUEST:
    
    // Configuration operations
    case FDB_CONFIGTRANSACTIONGETREQUEST:
    case FDB_CONFIGTRANSACTIONCOMMITREQUEST:
    case FDB_CONFIGFOLLOWERGETCHANGESREQUEST:
    case FDB_CONFIGBROADCASTCHANGESREQUEST:
    
    // Consistency and audit
    case FDB_INITIALIZECONSISTENCYSCANREQUEST:
    case FDB_HALTCONSISTENCYSCANREQUEST:
    
    // Interface FileIdentifiers (server roles)
    case FDB_STORAGESERVERINTERFACE:
    case FDB_GRVPROXYINTERFACE:
    case FDB_COMMITPROXYINTERFACE:
    case FDB_MASTERINTERFACE:
    case FDB_RATEKEEPERINTERFACE:
    case FDB_DATADISTRIBUTORINTERFACE:
    case FDB_TLOGINTERFACE:
    case FDB_RESOLVERINTERFACE:
    case FDB_BLOBWORKERINTERFACE:
    case FDB_BLOBMANAGERINTERFACE:
    case FDB_ENCRYPTKEYPROXYINTERFACE:
    case FDB_CONSISTENCYSCANINTERFACE:
    case FDB_WORKERINTERFACE:
    case FDB_CLUSTERINTERFACE:
    case FDB_PROCESSINTERFACE:
        return 1;
    default:
        return 0;
    }
}

static inline __attribute__((__always_inline__))
int is_known_reply_file_id(__u32 file_id) {
    // All FoundationDB replies use composed FileIdentifiers with ErrorOr wrapper (ID 2)
    // Format: (2 << 24) | base_file_identifier
    // Extract the base FileIdentifier from the lower 24 bits
    __u32 base_id = file_id & 0x00FFFFFF;

    switch (base_id) {
    // Core operation replies
    case FDB_GETVALUEREPLY:
    case FDB_GETKEYVALUESREPLY:  // Also covers STREAM and CHANGEFEED variants (same ID 1783066)
    case FDB_GETMAPPEDKEYVALUESREPLY:
    case FDB_GETKEYREPLY:
    case FDB_GETREADVERSIONREPLY:
    case FDB_ACKNOWLEDGEMENTREPLY:
    case FDB_VERSIONREPLY:  // Also covers WATCHVALUE and TLOGCOMMIT replies (same ID 3)
    case FDB_CHECKREPLY:
    
    // Transaction log replies
    case FDB_TLOGPEEKREPLY:
    case FDB_TLOGPEEKSTREAMREPLY:
    
    // Storage replies
    case FDB_GETSTORAGEMETRICSREPLY:
    case FDB_INITIALIZESTORAGEREPLY:
    case FDB_RECRUITSTORAGEREPLY:
    
    // Database and server info
    case FDB_GETCOMMITVERSIONREPLY:
    case FDB_GETSERVERDBINFOREPLY:
    case FDB_STATUSREPLY:
    case FDB_LOADEDREPLY:
    case FDB_REGISTERWORKERREPLY:
    
    // Network and monitoring
    case FDB_NETWORKTESTREPLY:
    case FDB_ECHOSERVERINTERFACE:
    
    // Blob storage replies
    case FDB_RECRUITBLOBWORKERREPLY:
    case FDB_INITIALIZEBLOBWORKERREPLY:
    case FDB_BLOBGRANULEFILEREPLY:
    case FDB_GETBLOBGRANULELOCATIONSREPLY:
    case FDB_MINBLOBVERSIONREPLY:
    
    // Configuration replies
    case FDB_GLOBALCONFIGREFRESHREPLY:
    case FDB_GETKEYSERVERLOCATIONSREPLY:
    case FDB_CONFIGTRANSACTIONGETREPLY:
    case FDB_CONFIGTRANSACTIONGETGENERATIONREPLY:
    case FDB_CONFIGFOLLOWERGETCHANGESREPLY:
    case FDB_CONFIGBROADCASTCHANGESREPLY:
    
    // Health and metrics
    case FDB_GETHEALTHMETRICSREPLY:
    case FDB_SPLITMETRICSREPLY:
    case FDB_PROTOCOLINFOREPLY:
    case FDB_CHECKDESCRIPTORMUTABLEREPLY:
    
    // Data structures and metadata
    case FDB_COMMITID:
    case FDB_RANGERESULTREF:
    case FDB_CLIENTDBINFO:
    case FDB_SERVERDBINFO:
    case FDB_UNIQUEGENERATION:
    case FDB_VOID:  // Used for acknowledgment responses (ping, commit, etc.)
        return 1;
    default:
        return 0;
    }
}


static inline __attribute__((__always_inline__))
int parse_fdb_packet(char *packet_start, int is_request) {
    // FoundationDB packet format:
    // Non-TLS: [Length(4)][Checksum(8)][EndpointToken(16)][RootOffset(4)][FileIdentifier(4)]
    // TLS:     [Length(4)][EndpointToken(16)][RootOffset(4)][FileIdentifier(4)]
    __u32 file_id;
    
    // Try non-TLS format first (FileIdentifier at offset 32)
    if (bpf_probe_read(&file_id, sizeof(file_id), packet_start + 32) == 0) {
        int is_valid = is_request ? is_known_fdb_operation(file_id) : is_known_reply_file_id(file_id);
        if (is_valid) {
            return 1;
        }
    }

    // Try TLS format (FileIdentifier at offset 24)  
    if (bpf_probe_read(&file_id, sizeof(file_id), packet_start + 24) == 0) {
        int is_valid = is_request ? is_known_fdb_operation(file_id) : is_known_reply_file_id(file_id);
        if (is_valid) {
            return 1;
        }
    }

    return 0;
}

static inline __attribute__((__always_inline__))
int is_foundationdb_request(char *payload, __u64 size) {
    if (is_foundationdb_connect_packet(payload)) {
        __u32 connect_length;
        if (bpf_probe_read(&connect_length, sizeof(connect_length), payload) != 0) {
            return 0;
        }
        __u32 actual_connect_size = connect_length + 4;
        
        if (size == actual_connect_size) {
            return 0;
        }
        
        if (size > actual_connect_size) {
            if (parse_fdb_packet(payload + actual_connect_size, 1)) {
                return 1;
            }
        }
        return 0;
    }

    return parse_fdb_packet(payload, 1);
}


static inline __attribute__((__always_inline__))
int is_foundationdb_response(char *payload, __u64 size, __s32 *status) {
    *status = STATUS_OK;
    
    if (is_foundationdb_connect_packet(payload)) {
        __u32 connect_length;
        if (bpf_probe_read(&connect_length, sizeof(connect_length), payload) != 0) {
            return 0;
        }
        __u32 actual_connect_size = connect_length + 4;
        
        if (size > actual_connect_size) {
            return parse_fdb_packet(payload + actual_connect_size, 0);
        }
        return 2;
    }
    return parse_fdb_packet(payload, 0);
}
