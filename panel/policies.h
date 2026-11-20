/* Included by server.c: bounded Keenetic reads and literal config updates. */
#define POLICY_MAX 64
#define POLICY_CONFIG_MAX (1024u * 1024u)
typedef struct { char id[64], name[256], mark[32]; } policy_item;
static int policy_id(const char *id) {
    if (!*id) return 1;
    for (const unsigned char *p=(const unsigned char *)id;*p;p++)
        if (!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'||*p=='.')) return 0;
    return strlen(id)<64;
}
static char *policy_trim(char *s) {
    while (*s==' '||*s=='\t') s++;
    char *e=s+strlen(s);
    while(e>s&&(e[-1]==' '||e[-1]=='\t'||e[-1]=='\r'||e[-1]=='\n')) *--e=0;
    return s;
}
static int policy_parse(char *text, policy_item *items, size_t *count) {
    *count=0; policy_item current={0}; char *save=NULL;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char *head=strstr(line,"policy, name = ");
        if(head) {
            memset(&current,0,sizeof current);
            char *id=head+15,*desc=strstr(id,", description = ");
            if(desc) {*desc=0;desc+=16;}
            char *comma=strchr(id,',');if(comma)*comma=0;
            id=policy_trim(id);size_t n=strlen(id);if(n&&id[n-1]==':')id[n-1]=0;
            id=policy_trim(id);
            if(!*id||!policy_id(id))continue;
            snprintf(current.id,sizeof current.id,"%s",id);
            if(desc){desc=policy_trim(desc);n=strlen(desc);if(n&&desc[n-1]==':')desc[n-1]=0;desc=policy_trim(desc);}
            if(desc&&strlen(desc)>=sizeof current.name)return -1;
            snprintf(current.name,sizeof current.name,"%s",desc&&*desc?desc:id);
        } else if(current.id[0]&&!strncmp(policy_trim(line),"mark:",5)) {
            char *mark=policy_trim(policy_trim(line)+5);size_t n=strlen(mark);
            if(!n||n>8)return -1;
            for(size_t i=0;i<n;i++)if(!((mark[i]>='0'&&mark[i]<='9')||(mark[i]>='a'&&mark[i]<='f')||(mark[i]>='A'&&mark[i]<='F')))return -1;
            if(*count>=POLICY_MAX)return -1;
            for(size_t i=0;i<*count;i++)if(!strcmp(items[i].id,current.id))return -1;
            snprintf(current.mark,sizeof current.mark,"%s",mark);items[(*count)++]=current;current.id[0]=0;
        }
    }
    return 0;
}
static int policy_list(const d2k_panel_config *cfg,int client,policy_item *items,size_t *count) {
    int pipes[2];if(pipe(pipes))return -1;
    pid_t pid=fork();if(pid<0){close(pipes[0]);close(pipes[1]);return -1;}
    if(!pid){
        if(setpgid(0,0))_exit(125);
        close(pipes[0]);if(dup2(pipes[1],STDOUT_FILENO)<0)_exit(125);close(pipes[1]);
        int nullfd=open("/dev/null",O_WRONLY);if(nullfd>=0){dup2(nullfd,STDERR_FILENO);close(nullfd);}
        if(client>2)close(client);
        if(cfg&&cfg->listener_fd>2)close(cfg->listener_fd);
        execlp("ndmc","ndmc","-c","show ip policy",(char*)NULL);_exit(127);
    }
    (void)setpgid(pid,pid);
    close(pipes[1]);char text[32768];size_t used=0;int ok=0,status=0;
    long long deadline=monotonic_ms()+1500;
    for(;;){
        long long left=deadline-monotonic_ms();if(left<=0)break;
        struct pollfd p={.fd=pipes[0],.events=POLLIN};int rc=poll(&p,1,(int)left);
        if(rc<0&&errno==EINTR)continue;
        if(rc<=0)break;
        ssize_t n=read(pipes[0],text+used,sizeof text-1-used);
        if(n<0&&errno==EINTR)continue;
        if(n<0)break;
        if(!n){ok=1;break;}used+=(size_t)n;if(used==sizeof text-1)break;
    }
    close(pipes[0]);
    if(!ok)(void)kill(-pid,SIGKILL);
    /* Even a child which closed stdout must finish within the same deadline. */
    for(;;){pid_t r=waitpid(pid,&status,WNOHANG);if(r==pid)break;
        if(r<0&&errno!=EINTR){ok=0;break;}
        if(monotonic_ms()>=deadline){ok=0;kill(-pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}break;}
        struct timespec pause={.tv_nsec=10000000};nanosleep(&pause,NULL);
    }
    /* The private group may outlive its already reaped leader. */
    (void)kill(-pid,SIGKILL);
    if(!ok||!WIFEXITED(status)||WEXITSTATUS(status))return -1;
    text[used]=0;return policy_parse(text,items,count);
}
static int policy_key(const char *line,size_t n,size_t *offset) {
    size_t i=0;while(i<n&&(line[i]==' '||line[i]=='\t'))i++;
    if(n-i>6&&!memcmp(line+i,"export",6)&&(line[i+6]==' '||line[i+6]=='\t')){i+=6;while(i<n&&(line[i]==' '||line[i]=='\t'))i++;}
    static const char key[]="KEENETIC_POLICY";
    if(n-i<sizeof key-1||memcmp(line+i,key,sizeof key-1))return 0;
    i+=sizeof key-1;while(i<n&&(line[i]==' '||line[i]=='\t'))i++;
    if(i==n||line[i]!='=')return 0;
    *offset=i+1;return 1;
}
/* Editing is supported only for physical, literal assignment lines. Reject
 * shell control syntax before interpreting any key, including keys inside
 * multiline values, continuations and heredocs. Never evaluate owner config. */
static int policy_config_layout(const char *raw) {
    for(const char *line=raw;*line;){
        const char *end=strchr(line,'\n');if(!end)end=line+strlen(line);
        const char *p=line;while(p<end&&(*p==' '||*p=='\t'||*p=='\r'))p++;
        if(p==end||*p=='#'){line=*end?end+1:end;continue;}
        if(end-p>6&&!memcmp(p,"export",6)&&(p[6]==' '||p[6]=='\t')){p+=6;while(p<end&&(*p==' '||*p=='\t'))p++;}
        if(p==end||!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||*p=='_'))return -1;
        while(p<end&&((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'))p++;
        while(p<end&&(*p==' '||*p=='\t'))p++;
        if(p==end||*p++!='=')return -1;
        char quote=0;int gap=0,started=0;
        for(;p<end;p++){
            char c=*p;
            if(quote=='\''){if(c=='\'')quote=0;continue;}
            if(c=='\\'){if(++p==end)return -1;started=1;continue;}
            if(c=='$'||c=='`')return -1;
            if(quote=='"'){if(c=='"')quote=0;continue;}
            if(c=='#'&&(!started||gap))break;
            if(c==' '||c=='\t'||c=='\r'){if(started)gap=1;continue;}
            if(gap)return -1;
            if(c=='\''||c=='"'){quote=c;started=1;continue;}
            if(c=='<'||c=='>'||c==';'||c=='|'||c=='&'||c=='('||c==')')return -1;
            started=1;
        }
        if(quote)return -1;
        line=*end?end+1:end;
    }
    return 0;
}
static char *policy_config_load(const char *path,struct stat *st) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW);if(fd<0)return NULL;
    if(fstat(fd,st)||!S_ISREG(st->st_mode)||st->st_size<0||(size_t)st->st_size>POLICY_CONFIG_MAX){close(fd);return NULL;}
    size_t len=(size_t)st->st_size,used=0;char *raw=malloc(len+1);if(!raw){close(fd);return NULL;}
    while(used<len){ssize_t n=read(fd,raw+used,len-used);if(n<0&&errno==EINTR)continue;if(n<=0){free(raw);close(fd);return NULL;}used+=(size_t)n;}
    close(fd);raw[len]=0;if(memchr(raw,0,len)||policy_config_layout(raw)){free(raw);return NULL;}return raw;
}
static int policy_config_read(const char *path,char *out,size_t cap) {
    if(!path)return -1;
    struct stat st;char *raw=policy_config_load(path,&st);if(!raw)return -1;
    out[0]=0;int rc=0;char *save=NULL;
    for(char *line=strtok_r(raw,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
        size_t off;if(!policy_key(line,strlen(line),&off))continue;
        char *v=policy_trim(line+off),*tail=NULL;
        if(*v=='\''||*v=='"'){char quote=*v++;tail=strchr(v,quote);if(!tail||(tail[1]&&tail[1]!=' '&&tail[1]!='\t'&&tail[1]!='\r')){rc=-1;break;}*tail++=0;tail=policy_trim(tail);if(*tail&&*tail!='#'){rc=-1;break;}}
        else {tail=strchr(v,'#');if(tail&&(tail==v||tail[-1]==' '||tail[-1]=='\t'))*tail=0;v=policy_trim(v);}
        if(strlen(v)>=cap){rc=-1;break;}snprintf(out,cap,"%s",v);
    }
    free(raw);return rc;
}
static int policy_config_save(const char *path,const char *id) {
    if(!path||!policy_id(id))return -1;
    struct stat st,now;char *raw=policy_config_load(path,&st);if(!raw)return -1;
    char temp[1024];int n=snprintf(temp,sizeof temp,"%s.policy.XXXXXX",path);if(n<0||(size_t)n>=sizeof temp){free(raw);return -1;}
    int fd=mkstemp(temp);if(fd<0){free(raw);return -1;}FILE *f=fdopen(fd,"w");int ok=f!=NULL,found=0;
    if(!f){close(fd);unlink(temp);free(raw);return -1;}
    /* Preserve ownership and access before installing; never widen secret config permissions. */
    struct stat created;if(fstat(fd,&created))ok=0;
    if(ok&&(created.st_uid!=st.st_uid||created.st_gid!=st.st_gid)&&fchown(fd,st.st_uid,st.st_gid))ok=0;
    if(fchmod(fd,st.st_mode&0777))ok=0;
    for(char *p=raw;ok&&*p;){char *end=strchr(p,'\n');size_t len=end?(size_t)(end-p)+1:strlen(p),off;
        if(policy_key(p,len,&off)){if(!found&&(fwrite(p,1,off,f)!=off||fprintf(f,"'%s'\n",id)<0))ok=0;found=1;}
        else if(fwrite(p,1,len,f)!=len)ok=0;
        p+=len;
    }
    if(ok&&!found){size_t len=strlen(raw);if(len&&raw[len-1]!='\n'&&fputc('\n',f)==EOF)ok=0;if(fprintf(f,"KEENETIC_POLICY='%s'\n",id)<0)ok=0;}
    if(fflush(f)||fsync(fd))ok=0;
    if(fclose(f))ok=0;
    /* Refuse replacement after an observed concurrent owner edit. */
    struct stat check;char *current=policy_config_load(path,&check);
    if(!current||check.st_size!=st.st_size||memcmp(raw,current,(size_t)st.st_size))ok=0;
    free(current);
    if(lstat(path,&now)||now.st_dev!=st.st_dev||now.st_ino!=st.st_ino||now.st_size!=st.st_size||now.st_mtime!=st.st_mtime||now.st_ctime!=st.st_ctime)ok=0;
    if(ok&&rename(temp,path))ok=0;
    if(!ok)unlink(temp);
    free(raw);return ok?0:-1;
}
static int policy_reply(int fd,int code,const char *message) {
    char text[1024]={0};panel_buf b={.p=text,.cap=sizeof text};buf_puts(&b,"{\"ok\":false,\"message\":");buf_json_string(&b,message);buf_puts(&b,"}");
    return response(fd,code,code==403?"Forbidden":code==409?"Conflict":code==400?"Bad Request":"Service Unavailable","application/json; charset=utf-8",text,b.len);
}
/* Match NUL-separated argv, never a substring in another argument. */
static int policy_argv_matches(const char *args,size_t len,const char *mark) {
    if (!len || strnlen(args,len)==len) return 0;
    const char *base=strrchr(args,'/');base=base?base+1:args;
    if(strcmp(base,"d2kd"))return 0;
    size_t at=0;int found=0;
    while(at<len){size_t n=strnlen(args+at,len-at);if(n==len-at)return 0;
        if(!strcmp(args+at,"--only-mark")){
            if(found++)return 0;
            at+=n+1;if(at>=len)return 0;n=strnlen(args+at,len-at);if(n==len-at)return 0;
            if(!mark||!*mark)return 0;
            char expected[64];snprintf(expected,sizeof expected,"0x%s/0xffffffff",mark);
            if(strcmp(args+at,expected))return 0;
        }
        at+=n+1;
    }
    return mark&&*mark?found==1:found==0;
}
static int policy_applied(const d2k_panel_config *cfg,const char *mark) {
    if(!cfg->engine_pid_path)return 0;
    FILE *f=fopen(cfg->engine_pid_path,"r");if(!f)return 0;long pid=0;char tail=0;
    int n=fscanf(f,"%ld %c",&pid,&tail);fclose(f);if(n!=1||pid<=1)return 0;
    char path[128];snprintf(path,sizeof path,"/proc/%ld/cmdline",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
    char args[16384];ssize_t used=read(fd,args,sizeof args);close(fd);
    return used>0&&(size_t)used<sizeof args&&policy_argv_matches(args,(size_t)used,mark);
}
/* Internal IDs always outrank descriptions; a description must be unique. */
static const policy_item *policy_resolve(const policy_item *items,size_t count,const char *selected) {
    for(size_t i=0;i<count;i++)if(!strcmp(items[i].id,selected))return &items[i];
    const policy_item *match=NULL;
    for(size_t i=0;i<count;i++)if(!strcmp(items[i].name,selected)){if(match)return NULL;match=&items[i];}
    return match;
}
static int api_policies(int fd,const d2k_panel_config *cfg,const char *req,const char *method) {
    int post=!strcmp(method,"POST");
    if(!post&&strcmp(method,"GET"))return response(fd,405,"Method Not Allowed","text/plain","method not allowed\n",19);
    if(post&&(!cfg||!cfg->control_enabled||!d2k_panel_same_origin(req)))return policy_reply(fd,403,"Управление разрешено только с этой панели");
    if(!cfg||!cfg->config_path)return policy_reply(fd,503,"Конфигурация недоступна");
    char selected[256];if(policy_config_read(cfg->config_path,selected,sizeof selected))return policy_reply(fd,503,"Не удалось прочитать выбранную политику");
    policy_item items[POLICY_MAX];size_t count=0;
    if(policy_list(cfg,fd,items,&count))return policy_reply(fd,503,"Не удалось получить политики Keenetic. Обновите список и повторите попытку.");
    d2k_panel_control_tick();
    if(post){
        const char *value=NULL,*length=NULL;size_t len=0,length_len=0;
        if(header_value(req,"Transfer-Encoding",&length,&length_len)||(header_value(req,"Content-Length",&length,&length_len)&&!(length_len==1&&*length=='0'))||!header_value(req,"X-D2K-Policy",&value,&len)||len>=64)return policy_reply(fd,400,"Недопустимый запрос политики");
        char id[64];memcpy(id,value,len);id[len]=0;
        if(!policy_id(id))return policy_reply(fd,400,"Недопустимый идентификатор политики");
        int found=!id[0];for(size_t i=0;i<count;i++)if(!strcmp(items[i].id,id))found=1;
        if(!found)return policy_reply(fd,409,"Политика больше не существует. Обновите список.");
        if(cfg->mode&&!strcmp(cfg->mode,"off"))return policy_reply(fd,409,"В config задан MODE=off; сначала включите движок");
        if(action_pid)return policy_reply(fd,409,"Предыдущая команда ещё выполняется");
        if(!cfg->service_path||!cfg->service_path[0]||access(cfg->service_path,X_OK))return policy_reply(fd,503,"Служба недоступна; политика не сохранена");
        if(policy_config_save(cfg->config_path,id))return policy_reply(fd,503,"Не удалось сохранить политику; проверьте конфигурацию");
        if(run_service_action(cfg,"engine-restart",fd)){policy_action=1;action_state="failed";return policy_reply(fd,503,"Политика сохранена, но перезапуск не запущен. Повторите применение.");}
        policy_action=1;
        static const char body[]="{\"ok\":true,\"state\":\"running\",\"message\":\"Политика сохранена. Проверяем применение…\"}";
        return response(fd,202,"Accepted","application/json; charset=utf-8",body,sizeof body-1);
    }
    char text[32768]={0};panel_buf b={.p=text,.cap=sizeof text};
    buf_puts(&b,"{\"ok\":true,\"selected\":");buf_json_string(&b,selected);
    buf_printf(&b,",\"controls_enabled\":%s,\"apply_state\":",cfg->control_enabled?"true":"false");buf_json_string(&b,policy_action?action_state:"unknown");
    const policy_item *resolved=selected[0]?policy_resolve(items,count,selected):NULL;
    const char *mark=resolved?resolved->mark:NULL;int known=!selected[0]||resolved;
    buf_puts(&b,",\"selected_id\":");
    if(known)buf_json_string(&b,resolved?resolved->id:"");else buf_puts(&b,"null");
    buf_printf(&b,",\"applied\":%s",known&&policy_applied(cfg,mark)?"true":"false");
    buf_puts(&b,",\"policies\":[");
    for(size_t i=0;i<count;i++){if(i)buf_puts(&b,",");buf_puts(&b,"{\"id\":");buf_json_string(&b,items[i].id);buf_puts(&b,",\"name\":");buf_json_string(&b,items[i].name);buf_puts(&b,"}");}
    buf_puts(&b,"]}");if(b.failed)return policy_reply(fd,503,"Список политик слишком велик");
    return response(fd,200,"OK","application/json; charset=utf-8",text,b.len);
}
