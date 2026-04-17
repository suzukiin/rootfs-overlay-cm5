#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// --- PROTÓTIPOS ---
char* read_file(const char* filename);
void init_snmp_session(const char *ip);
int discover_amplifiers(const char *base_oid_str, int *found_ids);
int get_snmp_int(const char *oid_str);
void process_amplifier(int amp_id, cJSON *amp_table);

// --- GLOBAIS ---
struct snmp_session session, *ss;

// --- LEITURA DE ARQUIVO ---
char* read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (data) {
        fread(data, 1, len, f);
        data[len] = '\0';
    }
    fclose(f);
    return data;
}

// --- INICIALIZAÇÃO SNMP V2c ---
void init_snmp_session(const char *ip) {
    init_snmp("jupiter_telemetry");
    snmp_sess_init(&session);
    session.peername = strdup(ip);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)"public"; // Altere se sua community for outra
    session.community_len = strlen((const char *)session.community);
    
    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("Erro ao abrir sessao SNMP", &session);
        exit(1);
    }
}

// --- DESCOBERTA DINÂMICA DE GAVETAS (WALK) ---
int discover_amplifiers(const char *base_oid_str, int *found_ids) {
    struct snmp_pdu *pdu, *response;
    oid root_oid[MAX_OID_LEN], current_oid[MAX_OID_LEN];
    size_t root_oid_len, current_oid_len;
    int count = 0;

    read_objid(base_oid_str, root_oid, &root_oid_len);
    memcpy(current_oid, root_oid, root_oid_len * sizeof(oid));
    current_oid_len = root_oid_len;

    while (1) {
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, current_oid, current_oid_len);
        
        int status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            struct variable_list *vars = response->variables;
            
            // Verifica se ainda estamos na mesma tabela de OIDs
            if (snmp_oid_compare(root_oid, root_oid_len, vars->name, root_oid_len) == 0) {
                int id = vars->name[vars->name_length - 1]; // O último dígito é o ID da gaveta
                found_ids[count++] = id;
                
                memcpy(current_oid, vars->name, vars->name_length * sizeof(oid));
                current_oid_len = vars->name_length;
            } else {
                if (response) snmp_free_pdu(response);
                break;
            }
        } else {
            if (response) snmp_free_pdu(response);
            break;
        }
        if (response) snmp_free_pdu(response);
    }
    return count;
}

// --- BUSCA VALOR INTEIRO VIA SNMP ---
int get_snmp_int(const char *oid_str) {
    struct snmp_pdu *pdu, *response;
    oid an_oid[MAX_OID_LEN];
    size_t an_oid_len = MAX_OID_LEN;
    int val = -1;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    read_objid(oid_str, an_oid, &an_oid_len);
    snmp_add_null_var(pdu, an_oid, an_oid_len);

    int status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->variables) {
        val = *response->variables->val.integer;
    }
    if (response) snmp_free_pdu(response);
    return val;
}

// --- PROCESSA CADA GAVETA ---
void process_amplifier(int amp_id, cJSON *amp_table) {
    const char *base_status_oid = cJSON_GetObjectItem(amp_table, "alerts_base_oid")->valuestring;
    cJSON *alerts_map = cJSON_GetObjectItem(amp_table, "alerts_map");
    cJSON *alert = NULL;

    printf("\n>>> ANALISANDO GAVETA ID: %d\n", amp_id);

    cJSON_ArrayForEach(alert, alerts_map) {
        int code = cJSON_GetObjectItem(alert, "code")->valueint;
        const char *label = cJSON_GetObjectItem(alert, "label")->valuestring;
        
        char full_oid[256];
        sprintf(full_oid, "%s.%d.1.1.%d", base_status_oid, amp_id, code);
        
        int status_val = get_snmp_int(full_oid);
        printf("Status [%-18s]: %d\n", label, status_val);
    }
}

// --- MAIN ---
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Uso: %s <IP_DO_TRANSMISSOR>\n", argv[0]);
        return 1;
    }

    // 1. Carrega Template
    char *json_raw = read_file("rs_xx9.json");
    cJSON *root = cJSON_Parse(json_raw);
    cJSON *amp_table = cJSON_GetObjectItem(root, "amplifier_table");

    // 2. Conecta ao Transmissor
    init_snmp_session(argv[1]);

    // 3. Discovery Real de Gavetas
    int discovery_list[32];
    const char *oid_temp = cJSON_GetObjectItem(amp_table, "base_oid_temp")->valuestring;
    int total_found = discover_amplifiers(oid_temp, discovery_list);

    printf("JUPITER: Descobertos %d amplificadores no IP %s\n", total_found, argv[1]);

    // 4. Loop de Leitura
    for (int i = 0; i < total_found; i++) {
        process_amplifier(discovery_list[i], amp_table);
    }

    // 5. Cleanup
    snmp_close(ss);
    cJSON_Delete(root);
    free(json_raw);
    return 0;
}