
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "keystore.h"
#include "utils.h"

keystore_t *new_keystore(char *psk_buf)
{
    keystore_t *head = (keystore_t *)malloc(sizeof(keystore_t));
    if (NULL==head) {
        ERR("failed to allocate keystore");
        return NULL;
    }
    memset(head, 0, sizeof(keystore_t));

    keystore_t *psk = head;
    char *ptr = (char*)psk_buf;
    char *psk_str = strtok_r((char*)psk_buf, ",", &ptr);
    while (psk_str) {
        char *sep = strchr(psk_str, ':');
        if (sep) {
            //DBG("psk_str=%s", psk_str);
            //sep = '\0';

            uint8_t *tmp_key = (uint8_t *)sep+1;
            uint8_t tmp_keylen = strlen(sep+1);

            /* check if key is in hex */
            if (tmp_keylen > 2 && tmp_key[0] == '0' && tmp_key[1] == 'x') {
                puts("hex key detected");
                uint8_t cnt = 0;
                /* check key length, odd */
                bool key_odd = false;
                if (tmp_keylen % 2) {
                    key_odd = true;
                }
                /* convert key */
                for (int i = 2; i < tmp_keylen; i = i+2) {
                    char tmp[3] = {0,0,0};
                    if (key_odd && i == 2) {
                        /* only use first char for first val */
                        tmp[0] = '0';
                        tmp[1] = tmp_key[i];
                        /* modify i */
                        i = 1;
                    }
                    else {
                        tmp[0] = tmp_key[i];
                        tmp[1] = tmp_key[i + 1];
                    }
                    uint8_t val = (uint8_t)strtol(tmp, NULL, 16);
                    //printf("DBG(str): 0x%c%c - 0x%02x%02x\n", tmp[0], tmp[1], tmp[0], tmp[1]);
                    //printf("DBG(int): 0x%02x\n", val);
                    tmp_key[cnt] = val;
                    cnt++;
                }
                /* update key length */
                tmp_keylen = cnt;
            }

            psk->id = (uint8_t*)psk_str;
            psk->id_length = sep-psk_str;
            psk->key = tmp_key;
            psk->key_length = tmp_keylen;
            printf("psk->id: ");
            for (int i = 0; i < psk->id_length; i++) {
                printf("%c", psk->id[i]);
            }
            puts("");
            printf("psk->key(str): ");
            for (int i = 0; i < psk->key_length; i++) {
                printf("%c", psk->key[i]);
            }
            puts("");
            printf("psk->key(hex): ");
            for (int i = 0; i < psk->key_length; i++) {
                printf("%02x", psk->key[i]);
            }
            puts("");

            psk->next = (keystore_t *)malloc(sizeof(keystore_t));
            if (NULL==psk->next) {
                ERR("failed to allocate keystore");
                return NULL;
            }
            psk = psk->next;
            memset(psk, 0, sizeof(keystore_t));
        }
        psk_str = strtok_r(NULL, ",", &ptr);
    }

    for (psk=head; psk && psk->id_length; psk=psk->next) {
        //psk->id[psk->id_length] = '\0';
        char *sep = strchr((char *)psk->id, ':');
        if (sep) {
            *sep = '\0';
        }
        //DBG("%s id=\"%s\", key=\"%s\"", __func__, psk->id, psk->key);
    }

    return head;
}

void free_keystore(keystore_t *keystore)
{
    while (keystore) {
        keystore_t *tmp = keystore;
        keystore = keystore->next;
        free(tmp);
    }
}
