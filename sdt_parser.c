/**
 *	SDT parser for PoC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <gelf.h>
#include <libelf.h>
#include <assert.h>

struct sdt_points {
	char *provider;
	char *name;
	char *args;
	GElf_Addr pc_offset;
	GElf_Addr sem_offset;
	struct sdt_points *next;
};

/* Prototype declaration */
struct sdt_points *parse_sdt(const char *filename);

struct sdt_points *parse_sdt(const char *filename)
{
	int fd = -1;
	size_t shstrndx;
	GElf_Addr sdt_base_addr = 0;
	GElf_Off sdt_base_offset = 0;
	GElf_Addr sdt_probes_addr = 0;
	GElf_Off sdt_probes_offset = 0;
	GElf_Off sdt_probes_virt_offset = 0;
	Elf* elf = NULL;
	Elf_Scn* sdtb_scn = NULL;
	Elf_Scn* note_scn = NULL;
	struct sdt_points *plist = NULL;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		perror("Cannot open filename");
		goto error;
	}

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
	{
		perror("Cannot open filename");
		goto error_fd;
	}
	
	elf_getshdrstrndx(elf, &shstrndx);
	
	/* Parse .stapsdt.base */
	while ((sdtb_scn = elf_nextscn(elf, sdtb_scn)))
	{
		GElf_Shdr shdr;
		if (gelf_getshdr(sdtb_scn, &shdr) == NULL)
			continue;
		if (shdr.sh_type != SHT_PROGBITS)
			continue;
		if (!(shdr.sh_flags & SHF_ALLOC))
			continue;

		const char* sh_name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (sh_name && !strcmp(".stapsdt.base", sh_name))
		{
			sdt_base_addr = shdr.sh_addr;
			sdt_base_offset = shdr.sh_offset;
		}
		if (sh_name && !strcmp(".probes", sh_name))
		{
			sdt_probes_addr = shdr.sh_addr;
			sdt_probes_offset = shdr.sh_offset;
		}
	}
	/* Set offset for semaphore */
	if (sdt_probes_offset) {
		sdt_probes_virt_offset = (sdt_probes_addr - sdt_probes_offset) 
			- (sdt_base_addr - sdt_base_offset);
	}

	while ((note_scn = elf_nextscn(elf, note_scn))) {
		GElf_Shdr shdr;
		if (gelf_getshdr(note_scn, &shdr) == NULL)
			continue;
		if (shdr.sh_type != SHT_NOTE)
			continue;
		if (shdr.sh_flags & SHF_ALLOC)
			continue;
		
		Elf_Data *data = elf_getdata(note_scn, NULL);
		size_t next;
		GElf_Nhdr nhdr;
		size_t name_off;
		size_t desc_off;
		for (size_t offset = 0;
				(next = gelf_getnote(data, offset, &nhdr, &name_off, &desc_off)) > 0;
				offset = next)
		{
			struct sdt_points *p;
			char *cdata;
			char *provider;
			char *name;
			char *args;

			p = (struct sdt_points*)malloc(sizeof(struct sdt_points));
			if (!p) {
				perror("Cannot allocate memory");
				/* TODO: Hanlde alloc failed in the middle of this loop */
				goto error;
			}
			
			cdata = ((char*)data->d_buf);
			if (strcmp(cdata + name_off, "stapsdt") || nhdr.n_type != 3)
				continue;

			union {
				Elf64_Addr a64[3];
				Elf32_Addr a32[3];
			} buf;

			Elf_Data dst =
			{
				&buf, ELF_T_ADDR, EV_CURRENT,
				gelf_fsize (elf, ELF_T_ADDR, 3, EV_CURRENT), 0, 0
			};
			assert(dst.d_size <= sizeof buf);
			
			if (nhdr.n_descsz < dst.d_size + 3)
				continue;

			Elf_Data src =
			{    
				cdata + desc_off, ELF_T_ADDR, EV_CURRENT,
				dst.d_size, 0, 0
			};

			if (gelf_xlatetom(elf, &dst, &src, 
						elf_getident (elf, NULL)[EI_DATA]) == NULL)
			{
				perror("Cannot open gelf_xlatetom");
				goto error;
			}
			
			provider = cdata + desc_off + dst.d_size;
			p->provider = (char *)malloc(strlen(provider) + 1);
			if (!p->provider) {
				perror("Cannot allocate memory");
				/* TODO: Hanlde alloc failed in the middle of this loop */
				goto error;
			}
			memcpy(p->provider, provider, strlen(provider) + 1);
			
			name = provider + strlen(provider) + 1;
			p->name = (char *)malloc(strlen(name) + 1);
			if (!p->name) {
				perror("Cannot allocate memory");
				/* TODO: Hanlde alloc failed in the middle of this loop */
				goto error;
			}
			memcpy(p->name, name, strlen(name) + 1);
			
			args = name + strlen(name) + 1;
			if (args < cdata + desc_off + nhdr.n_descsz) {
				p->args = (char *)malloc(strlen(args) + 1);
				if (!p->args) {
					perror("Cannot allocate memory");
					/* TODO: Hanlde alloc failed in the middle of this loop */
					goto error;
				}
			}
			memcpy(p->args, args, strlen(args) + 1);

			GElf_Addr base_ref;
			if (gelf_getclass(elf) == ELFCLASS32)
			{
				p->pc_offset = buf.a32[0];
				base_ref = buf.a32[1];
				p->sem_offset = buf.a32[2];
			} else {
				p->pc_offset = buf.a64[0];
				base_ref = buf.a64[1];
				p->sem_offset = buf.a64[2];
			}

			p->pc_offset += sdt_base_offset - base_ref;
			if (p->sem_offset)
				p->sem_offset += sdt_base_offset - base_ref - sdt_probes_virt_offset;

			p->next = NULL;
			if (plist == NULL) {
				plist = p;
			} else {
				struct sdt_points *tmp;
				tmp = plist;
				while (tmp->next) {
					tmp = tmp->next;
				}
				tmp->next = p;
			}
		}
	}

	elf_end(elf);
	close(fd);
	return plist;
error_fd:
	close(fd);
error:
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sdt_points *plist;
	struct sdt_points *p;

	plist = parse_sdt(argv[1]);
	if (plist) {
		printf("-------- SDT info from %s --------\n", argv[1]);
		for (p = plist; p; p = p->next) {
			printf("provider: %s\n", p->provider);
			printf("name: %s\n", p->name);
			printf("args: %s\n", p->args);
			printf("\n");
		}
	}

	return 0;
}
