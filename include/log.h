#define LOGFILE	"/home/mount.log"

extern FILE *logfile;

#define log_struct(st, field, format, typecast) \
  log_msg("    " #field " = " #format "\n", typecast st->field)

void log_msg(const char *format, ...);

FILE *log_open();
