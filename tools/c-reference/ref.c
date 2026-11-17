#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opendroneid.h"
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1;}
static size_t unhex(const char*s,uint8_t*out,size_t max){size_t n=0; while(s[0]&&s[1]&&n<max){int a=hexval(s[0]),b=hexval(s[1]); if(a<0||b<0)break; out[n++]=(uint8_t)(a*16+b); s+=2;} return n;}
static void pstr(const char*k,const char*s,int n){printf("\"%s\":\"",k);for(int i=0;i<n&&s[i];i++){unsigned char c=(unsigned char)s[i]; if(c==34||c==92){putchar(92);putchar(c);} else if(c<0x20||c>0x7e){putchar(92);printf("u%04x",c);} else putchar(c);} printf("\"");}
int main(int argc,char**argv){
  char line[4096]; int packmode = argc>1 && strcmp(argv[1],"pack")==0;
  while(fgets(line,sizeof line,stdin)){
    line[strcspn(line,"\r\n")]=0; if(!line[0])continue;
    uint8_t buf[2048]; size_t n=unhex(line,buf,sizeof buf);
    ODID_UAS_Data u; odid_initUasData(&u);
    if(packmode){
      int r=odid_message_process_pack(&u,buf,n);
      int nb=0,na=0; for(int i=0;i<ODID_BASIC_ID_MAX_MESSAGES;i++)nb+=u.BasicIDValid[i]; for(int i=0;i<ODID_AUTH_MAX_PAGES;i++)na+=u.AuthValid[i];
      printf("{\"hex\":\"%s\",\"result\":%d,\"basic\":%d,\"location\":%d,\"auth\":%d,\"selfid\":%d,\"system\":%d,\"operator\":%d}\n",line,r,nb,u.LocationValid,na,u.SelfIDValid,u.SystemValid,u.OperatorIDValid);
      continue;
    }
    if(n<ODID_MESSAGE_SIZE){printf("{\"hex\":\"%s\",\"type\":-1}\n",line);continue;}
    ODID_messagetype_t t=decodeOpenDroneID(&u,buf);
    printf("{\"hex\":\"%s\",\"type\":%d",line,(int)t);
    switch(t){
    case ODID_MESSAGETYPE_BASIC_ID:{ODID_BasicID_data*b=&u.BasicID[0]; printf(",\"id_type\":%d,\"ua_type\":%d,",b->IDType,b->UAType); pstr("uas_id",b->UASID,20); break;}
    case ODID_MESSAGETYPE_LOCATION:{ODID_Location_data*l=&u.Location; printf(",\"status\":%d,\"direction\":%.2f,\"speed_h\":%.2f,\"speed_v\":%.2f,\"lat\":%.7f,\"lon\":%.7f,\"alt_baro\":%.1f,\"alt_geo\":%.1f,\"height_type\":%d,\"height\":%.1f,\"h_acc\":%d,\"v_acc\":%d,\"baro_acc\":%d,\"speed_acc\":%d,\"ts_acc\":%d,\"timestamp\":%.1f",
      l->Status,l->Direction,l->SpeedHorizontal,l->SpeedVertical,l->Latitude,l->Longitude,l->AltitudeBaro,l->AltitudeGeo,l->HeightType,l->Height,l->HorizAccuracy,l->VertAccuracy,l->BaroAccuracy,l->SpeedAccuracy,l->TSAccuracy,l->TimeStamp); break;}
    case ODID_MESSAGETYPE_AUTH:{int p=0;for(int i=0;i<ODID_AUTH_MAX_PAGES;i++)if(u.AuthValid[i])p=i; ODID_Auth_data*a=&u.Auth[p]; printf(",\"page\":%d,\"auth_type\":%d,\"last_page\":%d,\"length\":%d,\"auth_ts\":%u",a->DataPage,a->AuthType,a->LastPageIndex,a->Length,a->Timestamp); break;}
    case ODID_MESSAGETYPE_SELF_ID:{printf(",\"desc_type\":%d,",u.SelfID.DescType); pstr("desc",u.SelfID.Desc,23); break;}
    case ODID_MESSAGETYPE_SYSTEM:{ODID_System_data*s=&u.System; printf(",\"op_loc_type\":%d,\"class_type\":%d,\"op_lat\":%.7f,\"op_lon\":%.7f,\"area_count\":%u,\"area_radius\":%u,\"area_ceiling\":%.1f,\"area_floor\":%.1f,\"cat_eu\":%d,\"class_eu\":%d,\"op_alt_geo\":%.1f,\"sys_ts\":%u",
      s->OperatorLocationType,s->ClassificationType,s->OperatorLatitude,s->OperatorLongitude,s->AreaCount,s->AreaRadius,s->AreaCeiling,s->AreaFloor,s->CategoryEU,s->ClassEU,s->OperatorAltitudeGeo,s->Timestamp); break;}
    case ODID_MESSAGETYPE_OPERATOR_ID:{printf(",\"op_id_type\":%d,",u.OperatorID.OperatorIdType); pstr("op_id",u.OperatorID.OperatorId,20); break;}
    default: break;}
    printf("}\n");
  }
  return 0;
}
