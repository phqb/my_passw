#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 16
#define IV_BYTE_LEN 16
#define SHA256_BYTE_LEN 32
#define ENTROPY_LEN 32

int 
byte_n_equals
(
    const unsigned char * lhs, 
    const unsigned char * rhs, 
    int count
) 
{
    assert(NULL != lhs);
    assert(NULL != rhs);

    for (int i = 0; i < count; i += 1)
        if (lhs[i] != rhs[i]) return 0;

    return 1;
}

int 
digest_message
(
    const unsigned char * message,
    int message_len,
    unsigned char ** out_digest
) 
{
    assert(EVP_MD_size(EVP_sha256()) == SHA256_BYTE_LEN);

    EVP_MD_CTX * mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

	if (1 != EVP_DigestUpdate(mdctx, message, message_len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

	if ((*out_digest = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return 1;

    unsigned int digest_len;
	if (1 != EVP_DigestFinal_ex(mdctx, *out_digest, &digest_len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SHA256_BYTE_LEN != digest_len) 
        return 1;


	EVP_MD_CTX_free(mdctx);

    return 0;
}

int 
get_iv
(
    int size, 
    unsigned char ** out_iv
) 
{
    assert(NULL != out_iv);

    if (ENTROPY_LEN != RAND_load_file("/dev/random", ENTROPY_LEN)) 
    {
        fprintf(stderr, "Unable to load random bytes\n");
        return 1;
    }

    *out_iv = malloc(size);
    if (1 != RAND_bytes(*out_iv, size)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}

int 
encrypt_chacha
(
    const unsigned char * plaintext, 
    int plaintext_len, 
    const unsigned char key[SHA256_BYTE_LEN], 
    const unsigned char iv[IV_BYTE_LEN], 
    unsigned char * ciphertext
) 
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int 
decrypt_chacha
(
    const unsigned char * ciphertext, 
    int ciphertext_len, 
    const unsigned char key[SHA256_BYTE_LEN], 
    const unsigned char iv[IV_BYTE_LEN], 
    unsigned char * plaintext
) 
{
    EVP_CIPHER_CTX * ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

void 
print_usage() 
{
    printf(

"Usage: \n\
  new <file> <secret>\n\
  ls <input file> <secret>\n\
  set <name> <username> <password> <input file> <secret>\n\
  del <name> <input file> <secret>\n"

    );
}

int 
hash_secret
(
    const char * secret, 
    const unsigned char iv[IV_BYTE_LEN], 
    unsigned char ** out_hashed_secret
) 
{
    assert(NULL != secret);
    assert(NULL != out_hashed_secret);

    int error_code = 0;

    unsigned char * iv_and_secret = NULL;

    do
    { 
        int secret_len = strlen(secret);
        int iv_and_secret_len = IV_BYTE_LEN + secret_len;
        iv_and_secret = malloc(iv_and_secret_len);
        
        memcpy(iv_and_secret, iv, IV_BYTE_LEN);
        memcpy(iv_and_secret + IV_BYTE_LEN, secret, secret_len);

        if (0 != digest_message(iv_and_secret, iv_and_secret_len, 
                                out_hashed_secret)) 
        {
            error_code = 1;
            break;
        }
    }
    while (0);

    if (NULL != iv_and_secret) free(iv_and_secret);

    return error_code;
}

int 
make_new
(
    const char * filename, const char * secret
) 
{
    assert(NULL != filename);
    assert(NULL != secret);

    int error_code = 0;

    unsigned char * iv = NULL;
    unsigned char * hashed_secret = NULL;

    do
    {
        FILE * fp = fopen(filename, "wb");
        if (NULL == fp) 
        {
            error_code = 1;
            break;
        }

        if (0 != get_iv(IV_BYTE_LEN, &iv))
        {
            error_code = 1;
            break;
        }

        if (0 != hash_secret(secret, iv, &hashed_secret))
        {
            error_code = 1;
            break;
        }

        fwrite(iv, 1, IV_BYTE_LEN, fp);
        fwrite(hashed_secret, 1, SHA256_BYTE_LEN, fp);
        fflush(fp);
        fclose(fp);
    }
    while (0);

    if (NULL != iv) free(iv);
    if (NULL != hashed_secret) free(hashed_secret);

    return error_code;
}

int 
read_iv
(
    FILE * file, unsigned char iv[IV_BYTE_LEN]
) 
{
    assert(NULL != file);

    if (IV_BYTE_LEN != fread(iv, 1, IV_BYTE_LEN, file)) 
    {
        fprintf(stderr, "Could not read IV\n");
        return 1;
    }

    return 0;
}

int 
read_to_buffer
(
    FILE * file, 
    unsigned char ** out_buffer
) 
{
    assert(NULL != file);
    assert(NULL != out_buffer);

    unsigned char BUFFER[BUFFER_SIZE];

    int total_read = 0;
    int num_read;
    do 
    {
        num_read = fread(BUFFER, 1, BUFFER_SIZE, file);
        if (num_read > 0) 
        {
            *out_buffer = realloc(*out_buffer, total_read + num_read);
            memcpy(*out_buffer + total_read, BUFFER, num_read);
            total_read += num_read;
        }
    } 
    while (num_read == BUFFER_SIZE);

    return total_read;
}

void
write_password_infos
(
    const char * name,
    int name_len,
    const char * username,
    int username_len,
    const char * password,
    int password_len,
    unsigned char ** buffer,
    int * buffer_len
) 
{
    assert(NULL != name);
    assert(NULL != username);
    assert(NULL != password);
    assert(NULL != buffer);
    assert(NULL != buffer_len);

    int line_len = name_len + username_len + password_len + 2;
    *buffer = realloc(*buffer, *buffer_len + line_len);

    memcpy(*buffer + *buffer_len, name, name_len);
    *buffer_len += name_len;

    memcpy(*buffer + *buffer_len, " ", 1);
    *buffer_len += 1;

    memcpy(*buffer + *buffer_len, username, username_len);
    *buffer_len += username_len;

    memcpy(*buffer + *buffer_len, " ", 1);
    *buffer_len += 1;

    memcpy(*buffer + *buffer_len, password, password_len);
    *buffer_len += password_len;
}

int 
upsert_or_delete
(
    int is_upsert,
    const unsigned char * input_buffer, 
    int input_buffer_len,
    const char * name,
    const char * username,
    const char * password,
    unsigned char ** output_buffer, 
    int * output_buffer_len
)
{
    assert(NULL != name);
    assert(NULL != output_buffer);
    assert(NULL != output_buffer_len);

    int name_len = strlen(name);
    int username_len = 0;
    if (NULL != username) username_len = strlen(username);
    int password_len = 0;
    if (NULL != password) password_len = strlen(password);

    *output_buffer_len = 0;

    int upserted = 0;
    int is_first_line = 1;

    int line_start = 0;
    int line_end = -1;

    for (int i = 0; i < input_buffer_len; i += 1) 
    {
        if (line_end >= 0) 
        {
            line_start = i;
            line_end = -1;
        }

        if ('\n' == input_buffer[i]) 
            line_end = i;
        else if (i == input_buffer_len - 1) 
            line_end = input_buffer_len;

        if (line_start == -1 || line_end == -1) continue;

        int name_start = line_start;
        int name_end = -1;

        for (int u = line_start; u < line_end; u += 1)
            if (' ' == input_buffer[u]) 
            {
                name_end = u;
                break;
            }

        if (name_end == -1) continue;

        if (name_end - name_start == name_len &&
            1 == byte_n_equals(input_buffer + name_start, 
                               (unsigned char *) name, name_len)) 
        {
            if (1 == is_upsert) 
            {
                if (0 == is_first_line) 
                {
                    *output_buffer = realloc(*output_buffer, 
                                             *output_buffer_len + 1);
                    memcpy(*output_buffer + *output_buffer_len, "\n", 1);
                    *output_buffer_len += 1;
                } else 
                {
                    is_first_line = 0;
                }

                write_password_infos(name, name_len, 
                                     username, username_len, 
                                     password, password_len, 
                                     output_buffer, output_buffer_len);

                upserted = 1;
            }
        } 
        else 
        {
            int line_len = line_end - line_start;

            if (0 == is_first_line) 
            {
                *output_buffer = realloc(*output_buffer, 
                                         *output_buffer_len + line_len + 1);
                memcpy(*output_buffer + *output_buffer_len, "\n", 1);
                *output_buffer_len += 1;
            }
            else 
            {
                *output_buffer = realloc(*output_buffer, 
                                         *output_buffer_len + line_len);
                is_first_line = 0;
            }

            memcpy(*output_buffer + *output_buffer_len, 
                   input_buffer + line_start, line_len);
            *output_buffer_len += line_len;
        }
    }

    if (1 == is_upsert && 0 == upserted) 
    {
        if (-1 != line_end) 
        {
            *output_buffer = realloc(*output_buffer, *output_buffer_len + 1);
            memcpy(*output_buffer + *output_buffer_len, "\n", 1);
            *output_buffer_len += 1;
        }

        write_password_infos(name, name_len, 
                             username, username_len, 
                             password, password_len, 
                             output_buffer, output_buffer_len);
    }

    return 0;
}

int 
ls
(
    const char * filename, 
    const char * secret
) 
{
    assert(NULL != filename);
    assert(NULL != secret);

    int error_code = 0;

    unsigned char iv[IV_BYTE_LEN];
    unsigned char expected_secret[SHA256_BYTE_LEN];

    unsigned char * hashed_secret = NULL;
    unsigned char * encrypted = NULL;
    unsigned char * decrypted = NULL;

    do
    {
        FILE * file = fopen(filename, "rb");
        if (NULL == file) 
        {
            error_code = 1;
            break;
        }

        if (0 != read_iv(file, iv)) 
        {
            error_code = 1;
            break;
        }

        if (0 != hash_secret(secret, iv, &hashed_secret))
        {
            error_code = 1;
            break;
        }

        if (SHA256_BYTE_LEN != fread(expected_secret, 1, SHA256_BYTE_LEN, file)) 
        {
            fprintf(stderr, "Could not read hashed secret\n");

            error_code = 1;
            break;
        }

        if (1 != byte_n_equals(expected_secret, hashed_secret, SHA256_BYTE_LEN)) 
        {
            fprintf(stderr, "Wrong secret!\n");

            error_code = 1;
            break;
        }

        int encrypted_len = read_to_buffer(file, &encrypted);

        fclose(file);

        if (encrypted_len > 0) 
        {
            decrypted = malloc(encrypted_len);

            if (0 != decrypt_chacha(encrypted, encrypted_len, 
                                    hashed_secret, iv, decrypted))
            {
                error_code = 1;
                break;
            }

            fwrite(decrypted, 1, encrypted_len, stdout);
            fwrite("\n", 1, 1, stdout);
            fflush(stdout);
        }
    }
    while (0);

    if (NULL != hashed_secret) free(hashed_secret);
    if (NULL != encrypted) free(encrypted);
    if (NULL != decrypted) free(decrypted);
    
    return error_code;
}

int 
set_or_del
(
    int is_setting,
    const char * filename, 
    const char * secret, 
    const char * name,
    const char * username, 
    const char * password
)
{
    assert(NULL != filename);
    assert(NULL != secret);
    assert(NULL != name);

    int error_code = 0;

    unsigned char iv[IV_BYTE_LEN];
    unsigned char expected_secret[SHA256_BYTE_LEN];

    unsigned char * hashed_secret = NULL;
    unsigned char * encrypted = NULL;
    unsigned char * decrypted = NULL;
    unsigned char * output = NULL;
    unsigned char * reencrypted = NULL;

    do
    {
        FILE * file = fopen(filename, "rb");
        if (NULL == file)
        {
            error_code = 1;
            break;
        } 

        if (0 != read_iv(file, iv))
        {
            error_code = 1;
            break;
        }

        if (0 != hash_secret(secret, iv, &hashed_secret))
        {
            error_code = 1;
            break;
        }

        if (SHA256_BYTE_LEN != fread(expected_secret, 1, SHA256_BYTE_LEN, file)) 
        {
            fprintf(stderr, "Could not read hashed secret\n");

            error_code = 1;
            break;
        }

        if (1 != byte_n_equals(expected_secret, hashed_secret, SHA256_BYTE_LEN)) 
        {
            fprintf(stderr, "Wrong secret!\n");

            error_code = 1;
            break;
        }

        int encrypted_len = read_to_buffer(file, &encrypted);

        fclose(file);

        if (encrypted_len > 0) 
        {
            decrypted = malloc(encrypted_len);

            if (0 != decrypt_chacha(encrypted, encrypted_len, 
                                    hashed_secret, iv, decrypted))
            {
                error_code = 1;
                break;
            }
        }

        int output_len;

        if (0 != upsert_or_delete(is_setting,
                                  decrypted,
                                  encrypted_len, 
                                  name,
                                  username,
                                  password,
                                  &output, 
                                  &output_len))
        {
            error_code = 1;
            break;
        }

        reencrypted = malloc(output_len);

        if (0 != encrypt_chacha(output, output_len, 
                                hashed_secret, iv, reencrypted))
        {
            error_code = 1;
            break;
        }

        FILE * output_file = fopen(filename, "wb");
        if (NULL == output_file) 
        {
            fprintf(stderr, "Could not open file to write\n");

            error_code = 1;
            break;
        }

        fwrite(iv, 1, IV_BYTE_LEN, file);
        fwrite(hashed_secret, 1, SHA256_BYTE_LEN, file);
        fwrite(reencrypted, 1, output_len, file);
        fflush(file);
        fclose(file);
    }
    while (0);

    if (NULL != hashed_secret) free(hashed_secret);
    if (NULL != encrypted) free(encrypted);
    if (NULL != decrypted) free(decrypted);
    if (NULL != output) free(output);
    if (NULL != reencrypted) free(reencrypted);

    return error_code;
}

int main(int argc, const char * argv[]) {
    switch (argc) {
        case 4:
            if (0 == strcmp("new\0", argv[1]))
            {
                if (0 != strlen(argv[2]) && 0 != strlen(argv[3]))
                    make_new(argv[2], argv[3]);
                else
                    print_usage();
            } 
            else if (0 == strcmp("ls\0", argv[1]))
            {
                if (0 != strlen(argv[2]) && 0 != strlen(argv[3]))
                    ls(argv[2], argv[3]);
                else 
                    print_usage();
            }
            else
                print_usage();

            break;
        case 5:
            if (0 == strcmp("del\0", argv[1]))
            {
                if (0 != strlen(argv[2]) && 0 != strlen(argv[3]) && 
                    0 != strlen(argv[4]))
                    set_or_del(0, argv[3], argv[4], argv[2], NULL, NULL);
                else
                    print_usage();
            }
            else
                print_usage();

            break;
        case 7:
            if (0 == strcmp("set\0", argv[1]))
            {
                if (0 != strlen(argv[2]) && 0 != strlen(argv[3]) && 
                    0 != strlen(argv[4]) && 0 != strlen(argv[5]) &&
                    0 != strlen(argv[6]))
                    set_or_del(1, argv[5], argv[6], argv[2], argv[3], argv[4]);
                else 
                    print_usage();
            }
            else 
                print_usage();

            break;
        default:
            print_usage();
    }

    return 0;
}
