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

// --- FUNÇÃO PARA LER O ARQUIVO JSON ---
char* read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = malloc(len + 1);
    if (data) {
        size_t read_len = fread(data, 1, len, f);
        data[read_len] = '\0';
    }
    fclose(f);
    return data;
}

// --- INICIALIZAÇÃO DA SESSÃO SNMP ---
void init_snmp_session(const char *ip) {
    init_snmp("jupiter_telemetry");
    snmp_sess_init(&session);
    session.peername = strdup(ip);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)"public"; // Ajuste se necessário
    session.community_len = strlen((const char *)session.community);
    
    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("Erro ao abrir sessao SNMP", &session);
        exit(1);
    }
}

// --- DESCOBERTA DE GAVETAS (SNMP WALK) ---
int discover_amplifiers(const char *base_oid_str, int *found_ids) {
    struct snmp_pdu *pdu, *response;
    oid root_oid[MAX_OID_LEN], current_oid[MAX_OID_LEN];
    size_t root_oid_len, current_oid_len;
    int count = 0;

    if (!snmp_parse_oid(base_oid_str, root_oid, &root_oid_len)) return 0;
    memcpy(current_oid, root_oid, root_oid_len * sizeof(oid));
    current_oid_len = root_oid_len;

    while (1) {
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, current_oid, current_oid_len);
        
        int status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS && response && response->errstat == SNMP_ERR_NOERROR) {
            struct variable_list *vars = response->variables;
            
            // Verifica se a OID retornada ainda faz parte da árvore que estamos varrendo
            if (vars && snmp_oid_compare(root_oid, root_oid_len, vars->name, root_oid_len) == 0) {
                // Pega o último índice da OID (ID da Gaveta)
                int id = vars->name[vars->name_length - 1];
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

// --- BUSCA VALOR INTEIRO (VERSÃO BLINDADA CONTRA SEGFAULT) ---
int get_snmp_int(const char *oid_str) {
    struct snmp_pdu *pdu, *response = NULL;
    oid an_oid[MAX_OID_LEN];
    size_t an_oid_len = MAX_OID_LEN;
    int val = -1;

    if (!snmp_parse_oid(oid_str, an_oid, &an_oid_len)) return -1;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, an_oid, an_oid_len);

    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response != NULL) {
        // Verifica se houve erro de "No Such Instance" ou similar
        if (response->errstat == SNMP_ERR_NOERROR && response->variables != NULL) {
            
            // Verifica o tipo do dado retornado para evitar cast inválido
            u_char type = response->variables->type;
            if (type == ASN_INTEGER || type == ASN_GAUGE || type == ASN_COUNTER || type == ASN_TIMETICKS) {
                val = (int)*response->variables->val.integer;
            } else {
                val = -2; // OID retornou algo que não é número
            }
        }
    }

    if (response) snmp_free_pdu(response);
    return val;
}

// --- PROCESSA CADA GAVETA INDIVIDUALMENTE ---
void process_amplifier(int amp_id, cJSON *amp_table) {
    if (!amp_table) return;

    const char *base_status_oid = cJSON_GetObjectItem(amp_table, "alerts_base_oid")->valuestring;
    cJSON *alerts_map = cJSON_GetObjectItem(amp_table, "alerts_map");
    cJSON *alert = NULL;

    printf("\n>>> ANALISANDO GAVETA ID: %d\n", amp_id);

    cJSON_ArrayForEach(alert, alerts_map) {
        int code = cJSON_GetObjectItem(alert, "code")->valueint;
        const char *label = cJSON_GetObjectItem(alert, "label")->valuestring;
        
        char full_oid[256];
        // Montagem robusta da string de OID
        snprintf(full_oid, sizeof(full_oid), "%s.%d.1.1.%d", base_status_oid, amp_id, code);
        
        int status_val = get_snmp_int(full_oid);
        
        // Se retornar -1, indica falha na leitura (timeout ou OID inválida)
        if (status_val < 0) {
            printf("Status [%-18s]: ERRO NA LEITURA (%d)\n", label, status_val);
        } else {
            printf("Status [%-18s]: %d\n", label, status_val);
        }
    }
}

// --- FUNÇÃO PRINCIPAL ---
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("JUPITER Telemetry - Erro: Informe o IP do transmissor.\n");
        printf("Uso: %s <IP_DO_TX>\n", argv[0]);
        return 1;
    }

    // 1. Carrega Template JSON
    char *json_raw = read_file("rs_xx9.json");
    if (!json_raw) {
        printf("Erro ao ler rs_xx9.json. Verifique se o arquivo existe.\n");
        return 1;
    }

    cJSON *root = cJSON_Parse(json_raw);
    if (!root) {
        printf("Erro no parse do JSON!\n");
        free(json_raw);
        return 1;
    }

    cJSON *amp_table = cJSON_GetObjectItem(root, "amplifier_table");

    // 2. Conecta ao Transmissor
    printf("Iniciando sessao SNMP para: %s\n", argv[1]);
    init_snmp_session(argv[1]);

    // 3. Discovery Dinâmico
    int discovery_list[32]; // Suporta até 32 gavetas
    const char *oid_temp = cJSON_GetObjectItem(amp_table, "base_oid_temp")->valuestring;
    
    int total_found = discover_amplifiers(oid_temp, discovery_list);

    if (total_found == 0) {
        printf("Aviso: Nenhum amplificador encontrado no IP %s. Verifique a rede/comunidade.\n", argv[1]);
    } else {
        printf("JUPITER: %d amplificadores identificados.\n", total_found);
        
        // 4. Varredura agnóstica
        for (int i = 0; i < total_found; i++) {
            process_amplifier(discovery_list[i], amp_table);
        }
    }

    // 5. Cleanup e Finalização
    printf("\nCiclo de leitura finalizado.\n");
    snmp_close(ss);
    cJSON_Delete(root);
    free(json_raw);

    return 0;
}