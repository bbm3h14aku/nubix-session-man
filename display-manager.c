#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wunused-value"

#include <libgen.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtk/gtk.h>

#include <smlog.h>
#include <nubix.h>

#include "pam.h"

#define KEY_ENTER	65293
#define KEY_ESC		65307

#define LOGIN_UI 			"login.ui"
#define WINDOW_ID			"window"
#define USERNAME_ID			"username_txt_entry"
#define PASSWORD_ID			"password_txt_entry"
#define STATUS_ID			"status_label"

#define ARG_DISPLAY 		"--display="
#define ARG_VT				"--vt="
#define ARG_RESO			"--screen-resolution="
#define ARG_THEME			"--theme="


#define DEF_DISPLAY			":1"
#define DEF_VT				"vt01"
#define DEF_RESO			"1024x768"
#define DEF_THEME			"default/"

static GtkEntry *user_txt_f;
static GtkEntry *pass_txt_f;
static GtkLabel *status_l;
static GtkLabel *datetime;
static pthread_t login_th;

// FLAG if timer continue
static gboolean continue_timer = FALSE;
// FLAG if timer has start working
static gboolean start_timer = FALSE;

static pid_t x_server_pid;
static pid_t clock_th;
static bool standalone = false;

static GtkLabel* datetime;

struct _sman_config {
	char display[4];
	char vt[4];
	char resolution_str[9];
	char theme[9];
};

static struct _sman_config config;

void preconfigure_setup(int argc, char **argv)
{
	if(argc == 2)
	{
		if(strcmp(argv[1], "--help") == 0 || argv[1][1] == 'h')
		{
			printf("usage %s %s %s %s\n", ARG_DISPLAY, ARG_VT, ARG_RESO, ARG_THEME);
			exit(0);
		}
		else
		{
			//TODO: rewrite config parser. POSIX errno 14 (Bad Address)
			smlogifoe("parsing config file ", argv[1]);
			FILE *cfg;
			if((cfg == fopen(argv[2], "r+")) != NULL)
			{
				char buf[64];
				while(fgets(buf, sizeof(buf), cfg) != NULL)
				{
					buf[strlen(buf) - 1] = '\0';
					if(buf[0] == '#')
						continue;
					if(strncmp(buf, ARG_DISPLAY, strlen(ARG_DISPLAY)) == 0)
					{
						char *display = strstr((const char *) buf, (const char *) "=");
						*display++;
						smlogdbge("setting display to ", display);
						strcpy((char *) config.display, display);
					}
					else if(strncmp(buf, ARG_VT, strlen(ARG_VT)) == 0)
					{
						char *vt = strstr(buf, "=");
						*vt++;	
						smlogdbge("setting vt to ", vt);
						strcpy((char *) config.vt, vt);
					}
					else if(strncmp(buf, ARG_RESO, strlen(ARG_RESO)) == 0)
					{
						char *reso = strstr(buf, "=");
						*reso++;
						smlogdbge("setting display-resolution to ", reso);
						strcpy((char *) config.resolution_str, reso);
					}
					else if(strncmp(buf, ARG_THEME, strlen(ARG_THEME)) == 0)
					{
						char *theme = strstr(buf, "=");
						*theme++;
						smlogdbge("setting theme to ", theme);
						strcpy((char *) config.theme, theme);
					}
				}
			}
			else
			{
				smlogerr();
				exit(1);
			}
		}
	}
	else if(argc >= 5)
	{
		for(int i = 0; i < argc; i++)
		{
			if(strncmp(argv[i], ARG_DISPLAY, strlen(ARG_DISPLAY)) == 0)
			{
				char *display = strstr((const char *) argv[i], (const char *) "=");
				*display++;
				smlogdbge("setting display to ", display);
				strcpy((char *) config.display, display);
			}
			else if(strncmp(argv[i], ARG_VT, strlen(ARG_VT)) == 0)
			{
				char *vt = strstr(argv[i], "=");
				*vt++;
				smlogdbge("setting vt to ", vt);
				strcpy((char *) config.vt, vt);
			}
			else if(strncmp(argv[i], ARG_RESO, strlen(ARG_RESO)) == 0)
			{
				char *reso = strstr(argv[i], "=");
				*reso++;
				smlogdbge("setting display-resolution to ", reso);
				strcpy((char *) config.resolution_str, reso);
			}
			else if(strncmp(argv[i], ARG_THEME, strlen(ARG_THEME)) == 0)
			{
				char *theme = strstr(argv[i], "=");
				*theme++;
				smlogdbge("setting theme directory to ", theme);
				strcpy((char *) config.theme, theme);
			}
		}
	}
	else
	{
		smlogwarn("falling back to default values");
		strcpy((char *) config.display, DEF_DISPLAY);
		strcpy((char *) config.vt, DEF_VT);
		strcpy((char *) config.resolution_str, DEF_RESO);
		strcpy((char *) config.theme, DEF_THEME);
	}
}

static gboolean update_timestr(gpointer data)
{
	char *timestr = gettimestamp();
	gtk_label_set_text(datetime, timestr);
	free(timestr);
	return continue_timer;
}

void _start_timer()
{
	smlogifo("installing timer set timet interval to 1 Second");
	g_timeout_add_seconds(1, update_timestr, NULL) ;
	start_timer =TRUE;
	continue_timer = TRUE;
}

//TODO: enable precheck for xserver argument list to prevent priv-escalation
static void start_x_server(const char *display, const char *vt)
{
	smlogifo("Starting xserver ... ");
	x_server_pid = fork();
	if(x_server_pid == 0)
	{
		char cmd[64];

		if((display != NULL && vt != NULL) && (strlen(display) > 0 && strlen(vt) > 0))
		{
#ifdef DEBUG
			snprintf(cmd, sizeof(cmd), "/usr/bin/Xephyr -ac -br -screen %s %s", config.resolution_str, config.display);
#else
			snprintf(cmd, sizeof(cmd), "/usr/bin/X %s %s", display, vt);
#endif
			smlogifoe("try to start ", cmd);
			execl("/bin/bash", "/bin/bash", "-c", cmd, NULL);
			printf("failed to start X-Server");
			exit(EXIT_FAILURE);
		}
		else
		{
			smlogmsg(SMLOGLVL_ERR, "failed to verify display and vt.");
			exit(1);
		}
	}
	else
	{
		//TODO: wait for xserver to start
		smlogifo("waiting for x-server to come online ... ");
		sleep(1);
	}
}

static void stop_x_server()
{
	smlogifo("stopping X-Server");
	if(x_server_pid != 0)
		kill(x_server_pid, SIGKILL);
}

static void* system_poweroff(void *data)
{
	smlogifo("handle system portweroff request");
	if(x_server_pid > 0)
		stop_x_server();

	if(clock_th != 0)
		kill(clock_th, SIGKILL);

//TODO: fix Gdk-Message: Fatal IO error 11 on X server :1
	gtk_main_quit();
	return NULL;
}

static void sig_handler(int signo)
{
	stop_x_server();
}

static void* cancel_func(void *data)
{
	GtkWidget *widget = GTK_WIDGET(data);
	gtk_entry_set_text(user_txt_f, "");
	gtk_entry_set_text(pass_txt_f, "");
	return NULL;
}

static void* login_func(void *data)
{
	GtkWidget *widget = GTK_WIDGET(data);
	const gchar *username = gtk_entry_get_text(user_txt_f);
	const gchar *password = gtk_entry_get_text(pass_txt_f);

	gtk_label_set_text(status_l, "Logging in ...");
	pid_t child_pid;
	if(login(username, password, &child_pid))
	{
		gtk_widget_hide(widget);

		smlogifo("Waiting for child ... \n");

		int status;
		waitpid(child_pid, &status, 0);

		//TODO: bug check on real maschine, does the login manager change run state?
		gtk_widget_show(widget);
		gtk_label_set_text(status_l, "");
			//logout();
	}
	else
	{
		gtk_label_set_text(status_l, "Login error username/password missmatch\n");
		gtk_widget_set_name(GTK_WIDGET(status_l), "status_error");
		gtk_widget_show(widget);
	}
	gtk_entry_set_text(pass_txt_f, "");
	return NULL;
}

static gboolean key_event(GtkWidget *widget, GdkEventKey *event)
{
	if(event->keyval == KEY_ENTER)
		pthread_create(&login_th, NULL, login_func, (void *) widget);
	else if(event->keyval == KEY_ESC)
		system_poweroff(NULL);
	return false;
}

int main(int argc, char** argv)
{
	smlog_enable();
	preconfigure_setup(argc, argv);

	pid_t clock;
	smlogifoe("connecting with xserver on display ", config.display);

#ifndef DEBUG
	if(nubix_xprobe() != 0)
	{
#endif
		signal(SIGSEGV, sig_handler);
		signal(SIGTRAP, sig_handler);
		start_x_server(config.display, config.vt);
		standalone = true;
#ifndef DEBUG
	}
#endif
	setenv("DISPLAY", config.display, true);

	smlogifo("enable multithreading");
	g_thread_init(NULL);
	gdk_threads_init();
	gdk_threads_enter();

	smlogifo("setting up gtk environment");
	gtk_init(&argc, &argv);

	char ui_fp[256];
	if(readlink("/proc/self/exe", ui_fp, sizeof(ui_fp)) == -1)
	{
		printf("Error: could not get location of binary\n");
		exit(EXIT_FAILURE);
	}

	dirname(ui_fp);
	strcat(ui_fp, "/res/" LOGIN_UI);
	GtkBuilder *builder = gtk_builder_new_from_file(ui_fp);

	GtkCssProvider *provider = gtk_css_provider_new();
	gtk_css_provider_load_from_path(provider, "res/login.css", NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

	GtkWindow *window = GTK_WINDOW(gtk_builder_get_object(builder, WINDOW_ID));
	gtk_widget_set_name(GTK_WIDGET(window), "window");
	user_txt_f = GTK_ENTRY(gtk_builder_get_object(builder, USERNAME_ID));
	pass_txt_f = GTK_ENTRY(gtk_builder_get_object(builder, PASSWORD_ID));
	status_l = GTK_LABEL(gtk_builder_get_object(builder, STATUS_ID));

	GtkFixed *fixlay = GTK_FIXED(gtk_builder_get_object(builder, "win_layout"));

	GtkButton *login = GTK_BUTTON(gtk_builder_get_object(builder, "btn_login"));
	GtkButton *cancel = GTK_BUTTON(gtk_builder_get_object(builder, "btn_cancel"));
	GtkButton *shutdown = GTK_BUTTON(gtk_builder_get_object(builder, "btn_shutdown"));
	datetime = GTK_LABEL(gtk_builder_get_object(builder,  "lbl_timestr"));

	GtkBox *box =GTK_BOX(gtk_builder_get_object(builder, "login_box"));
	gtk_widget_set_name(GTK_WIDGET(box), "login_box");

	GdkCursor *csr = gdk_cursor_new_for_display(gdk_display_get_default(), GDK_ARROW);

	// enabling fullscreen
	GdkScreen *screen = gdk_screen_get_default();
	char *width_cstr = strtok(config.resolution_str, "x");
	char *height_cstr = strtok(NULL, "x");

	gint height = atoi(height_cstr);
	gint width = atoi(width_cstr);

	
	gint d_h = gdk_screen_get_height(screen);
	gint d_w = gdk_screen_get_width(screen);

	char log[128];
	sprintf((char *) &log, "setting virtual screen size to Width=%d, Height=%d", width, height);
	smlogifo(log);

	if(d_h != height || d_w != width)
		smlogdbg("login window is under/over -scaled!");

	gtk_widget_set_size_request(GTK_WIDGET(window), height, width);

	gint box_height, box_width;
	nubix_widget_get_preferred_size(GTK_WIDGET(box), &box_height, &box_width);

	char *log_ext = (char *) malloc(sizeof(char) * 128);

	smlogifo("adjusting widget position on screen ...");

	gint center_h = (height / 2);
	gint center_w = (width / 2);

	gint x = center_w - (box_width / 2);
	gint y = center_h - (box_height / 2);

	gtk_fixed_move(fixlay, GTK_WIDGET(box), x, y);
	snprintf(log_ext, 128, "moving widget login_box to x=%d y=%d", x, y);
	smlogifo(log_ext);

	gint datetime_h, datetime_w;
	nubix_widget_get_preferred_size(GTK_WIDGET(datetime), &datetime_h, &datetime_w);
	
	x = center_w - (datetime_w / 2);
	gtk_fixed_move(fixlay, GTK_WIDGET(datetime), x, 0);
	snprintf(log_ext, 128, "moving widget datetime to x=%d y=%d", x, 0);
	smlogifo(log_ext);

	gint shutdown_h, shutdown_w;
	nubix_widget_get_preferred_size(GTK_WIDGET(shutdown), &shutdown_w, &shutdown_h);
	gtk_fixed_move(fixlay, GTK_WIDGET(shutdown), width - (shutdown_w * 3), 10);
	snprintf(log_ext, 128, "moving widget shutdown to x=%d y=%d", width - shutdown_w, 10);
	smlogifo(log_ext);

	gtk_widget_show_all(GTK_WIDGET(window));
	g_object_unref(builder);
	_start_timer();

	g_signal_connect(login, "clicked", G_CALLBACK(login_func), NULL);
	g_signal_connect(cancel, "clicked", G_CALLBACK(cancel_func), NULL);
	g_signal_connect(window, "key-release-event", G_CALLBACK(key_event), NULL);
	g_signal_connect(window, "destroy", G_CALLBACK(system_poweroff), NULL);
	g_signal_connect(shutdown, "clicked", G_CALLBACK(system_poweroff), NULL);

	gtk_main();
	gdk_threads_leave();

	if(standalone)
		stop_x_server();

	return 0;
}
