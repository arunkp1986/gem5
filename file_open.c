#include <stdio.h>

struct list_head
{
    struct list_head *next, *prev;
};

int main(){
    FILE *fp = fopen("./PhyMem.1","r");
    struct list_head p;
    char magic[6];
    fseek(fp,536870912,SEEK_SET);
    fread(magic,6,1,fp);
    magic[6] = '\0';
    printf("%s\n",magic);
    fseek(fp,536870944,SEEK_SET);
    fread(&p,sizeof(struct list_head),1,fp);
    printf("prev: %p, next: %p\n",p.prev,p.next);
    fclose(fp);

}
