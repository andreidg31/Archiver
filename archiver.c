#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef union record {
    char charptr[512];
    struct header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[8];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    } header;
} record;
void init_record(record *r) {
    for (int i = 0; i < 512; i++)
        (*r).charptr[i] = 0;
    (*r).header.typeflag = '0';
    for (int i = 0; i < 7; i++) {
        (*r).header.size[i] = '0';
        (*r).header.mode[i] = '0';
        (*r).header.uid[i] = '0';
        (*r).header.gid[i] = '0';
    }
    for (int i = 0; i < 11; i++) {
        (*r).header.mtime[i] = '0';
        (*r).header.size[i] = '0';
    }
}
void set_permisions(char *perm, char mode[8]) {
    int offset = 4;
    for (int i = 0; i < 3; i++) {
        if (perm[i * 3 + 1] == 'r') {
            mode[offset + i] += 4;
        }
        if (perm[i * 3 + 2] == 'w') {
            mode[offset + i] += 2;
        }
        if (perm[i * 3 + 3] == 'x') {
            mode[offset + i] += 1;
        }
    }
}
void place_octal(int number, int offset, char *target) {
    int size = strlen(target);
    for (int i = 0; i < size && number > 0; i++, number = number / 8) {
        target[offset - i - 1] += number % 8;
    }
}
struct tm parse_time(char *datetime_string) {
    struct tm time;
    int year = 70;
    int month = 0;
    int day = 1;
    int hour = 0;
    int minute = 0;
    int second = 0;
    sscanf(datetime_string, "%4d-%2d-%2d %2d:%2d:%2d",
        &year, &month, &day, &hour, &minute, &second);
    time.tm_year = year - 1900;
    time.tm_mon = month - 1;
    time.tm_mday = day;
    time.tm_hour = hour;
    time.tm_min = minute;
    time.tm_sec = second;
    time.tm_isdst = -1;
    return time;
}
void set_mtime(char *datetime_string, char mtime[12]) {
    time_t start_time;
    time_t curr_time;
    struct tm start_tm = parse_time("1970-01-01 00:00:00");
    struct tm curr_tm = parse_time(datetime_string);
    start_time = mktime(&start_tm);
    curr_tm.tm_hour = curr_tm.tm_hour - 2;
    curr_time = mktime(&curr_tm);
    place_octal((int)difftime(curr_time, start_time), 11, mtime);
}
void set_chksum(record *r) {
    int num = 0;
    for (int i = 0; i < 512; i++) {
        num += (int)(*r).charptr[i];
    }
    for (int i = 0; i < 8; i++) {
        num = num - (int)(*r).header.chksum[i] + 32;
    }
    for (int i = 0; i< 6; i++) {
        (*r).header.chksum[i] = '0';
    }
    (*r).header.chksum[6] = 0;
    (*r).header.chksum[7] = 32;
    place_octal(num, 6, (*r).header.chksum);
}
void get_ids(char *user, record *rec, FILE *f) {
    char line[512];
    char *token;
    while (fgets(line, 512, f)) {
        token = strtok(line, ":");
        if (!strcmp(user, token)) {
            token = strtok(NULL, ":");
            token = strtok(NULL, ":");
            place_octal(atoi(token), 7, (*rec).header.uid);
            token = strtok(NULL, ":");
            place_octal(atoi(token), 7, (*rec).header.gid);
            return;
        }
    }
}
int write_file(int size, record *r, char *filename, char *archivename) {
    FILE *f = fopen(archivename, "ab");
    FILE *read_file = fopen(filename, "rb");
    if (read_file == NULL) {
        return 0;
    }
    fwrite((*r).charptr, 512, 1, f);
    int tsize = (size / 512) * 512;
    if (size % 512 != 0) {
        tsize += 512;
    }
    char c;
    for (int i = 0; i < size; i++) {
        fread(&c, 1, 1, read_file);
        fwrite(&c, 1, 1, f);
    }
    c = 0;
    for (int i = size; i < tsize; i++) {
        fwrite(&c, 1, 1, f);
    }
    fclose(f);
    fclose(read_file);
    return 1;
}
void create() {
    int size = 0;
    char archive_name[50];
    char dirname[50];
    char filename[100];
    scanf("%s", archive_name);
    scanf("%s", dirname);
    char line[512];
    char *token;
    FILE *filelist = fopen("files.txt", "rt");
    FILE *userlist = fopen("usermap.txt", "rt");
    FILE *f = fopen(archive_name, "wb");
    fclose(f);
    record rec;
    while (fgets(line, 512, filelist)) {
        init_record(&rec);
        // In momentul acesta token-ul reprezinta permisiunile
        token = strtok(line, " ");
        set_permisions(token, rec.header.mode);
        token = strtok(NULL, " ");
        // In momentul acesta token-ul reprezinta numele ownerului
        token = strtok(NULL, " ");
        strcat(rec.header.uname, token);
        // In momentul acesta token-ul reprezinta numele grupului ownerului
        token = strtok(NULL, " ");
        strcat(rec.header.gname, token);
        // In momentul acesta token-ul reprezinta marimea in bytes a fisierului
        token = strtok(NULL, " ");
        size = atoi(token);
        place_octal(size, 11, rec.header.size);
        // Tokenul reprezinta data si timpul de la ultima modificare
        token = strtok(NULL, ".");
        set_mtime(token, rec.header.mtime);
        token = strtok(NULL, " ");
        token = strtok(NULL, " ");
        // Tokenul reprezinta numele
        token = strtok(NULL, " \n");
        strcat(rec.header.name, token);
        strcat(rec.header.linkname, token);
        strcat(rec.header.magic, "GNUtar ");
        get_ids(rec.header.uname, &rec, userlist);
        filename[0] = '\0';
        strcat(filename, dirname);
        strcat(filename, rec.header.name);
        printf("%s\n", filename);
        set_chksum(&rec);
        if (!write_file(size, &rec, filename, archive_name)) {
            printf("> Failed!\n");
            fclose(filelist);
            fclose(userlist);
            return;
        }
    }
    f = fopen(archive_name, "ab");
    record empty;
    for (int i = 0; i< 512; i++) {
        empty.charptr[i] = 0;
    }
    fwrite(empty.charptr, 1, 512, f);
    fclose(f);
    fclose(filelist);
    fclose(userlist);
    printf("> Done!\n");
}

int get_size(char ssize[12]) {
    int pow = 1;
    int size = 0;
    for (int i = 10; i >=0; i--) {
        size += ((int)(ssize[i] - '0')) * pow;
        pow*=8;
    }
    return size;
}
void list() {
    char empty[12];
    for (int i = 0; i < 11; i++) {
        empty[i] = 0;
    }
    char archivename[50];
    scanf("%s", archivename);
    FILE *f = fopen(archivename, "rb");
    if (f == NULL) {
        printf("> File not found!\n");
        return;
    }
    // Parcurgem arhiva
    record r;
    fread(r.charptr, 1, 512, f);
    while (!feof(f) && strcmp(empty, r.header.size)) {
        printf("> %s\n", r.header.name);
        int size = get_size(r.header.size);
        int no_steps = size / 512;
        if (size % 512 != 0) {
            no_steps++;
        }
        no_steps = no_steps * 512;
        fseek(f, no_steps, SEEK_CUR);
        fread(r.charptr, 1, 512, f);
    }
    fclose(f);
}
void extract() {
    char archive[100];
    char filename[200];
    char newfilename[200];
    newfilename[0] = 0;
    char empty[12];
    for (int i = 0; i < 11; i++) {
        empty[i] = 0;
    }
    scanf("%s%s", filename, archive);
    FILE *f = fopen(archive, "rb");
    if (f == NULL) {
        printf("> File not found!\n");
        return;
    }
    strcat(newfilename, "extracted_");
    strcat(newfilename, filename);
    // Aceeasi parcurgere ca si la list
    record r;
    fread(r.charptr, 1, 512, f);
    while (!feof(f) && strcmp(empty, r.header.size)) {
        int size = get_size(r.header.size);
        int no_steps = size / 512;
        if (size % 512 != 0) {
            no_steps++;
        }
        no_steps = no_steps * 512;
        if (!strcmp(filename, r.header.name)) {
            FILE *nf = fopen(newfilename, "wb");
            char c;
            for (int i = 0; i < size; i++) {
                fread(&c, 1, 1, f);
                fwrite(&c, 1, 1, nf);
            }
            fclose(nf);
            fclose(f);
            printf("> Done!\n");
            return;
        }
        fseek(f, no_steps, SEEK_CUR);
        fread(r.charptr, 1, 512, f);
    }
    printf("> File not found!\n");
    fclose(f);
}

int main() {
    char command[50];
    while (1) {
        scanf("%s", command);
        if (!strcmp(command, "create")) {
            create();
        } else if (!strcmp(command, "list")) {
            list();
        } else if (!strcmp(command, "extract")) {
            extract();
        } else if (!strcmp(command, "exit")) {
            return 0;
        } else {
            printf("Wrong Command!\n");
        }
    }
    return 0;
}
