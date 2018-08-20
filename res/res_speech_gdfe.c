/*
 * res_speech_gdfe -- an Asterisk speech driver for Google DialogFlow for Enterprise
 * 
 * Copyright (C) 2018, USAN, Inc.
 * 
 * Daniel Collins <daniel.collins@usan.com>
 * 
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source asterisk tree.
 *
 */

/*** MODULEINFO
    <depend>res_speech</depend>
	<depend>dfegrpc</depend>
 ***/

#include <asterisk.h>
#include <asterisk/module.h>
#include <asterisk/lock.h>
#include <asterisk/linkedlists.h>
#include <asterisk/cli.h>
#include <asterisk/term.h>
#include <asterisk/speech.h>

#ifdef RAII_VAR
#define ASTERISK_13_OR_LATER
#endif

#ifdef ASTERISK_13_OR_LATER
#include <asterisk/format.h>
#include <asterisk/format_cache.h>
#include <asterisk/codec.h>
#include <asterisk/format_cap.h>
#else
#include <asterisk/frame.h>
#include <asterisk/astobj2.h>
#endif

#include <asterisk/config.h>
#include <asterisk/ulaw.h>

#include <libdfegrpc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define GDF_PROP_SESSION_ID_NAME	"session_id"
#define GDF_PROP_PROJECT_ID_NAME	"project_id"
#define GDF_PROP_LANGUAGE_NAME		"language"
#define VAD_PROP_VOICE_THRESHOLD	"voice_threshold"
#define VAD_PROP_VOICE_DURATION		"voice_duration"
#define VAD_PROP_SILENCE_DURATION	"silence_duration"

enum VAD_STATE {
	VAD_STATE_START,
	VAD_STATE_SPEAK,
	VAD_STATE_SILENT
};

struct gdf_pvt {
	ast_mutex_t lock;
	struct dialogflow_session *session;
	
	enum VAD_STATE vad_state;
	int vad_state_duration; /* ms */
	int vad_change_duration; /* ms -- cumulative time of "not current state" audio */

	int voice_threshold; /* 0 - (2^16 - 1) */
	int voice_minimum_duration; /* ms */
	int silence_minimum_duration; /* ms */
	
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(session_id);
		AST_STRING_FIELD(event);
		AST_STRING_FIELD(language);
		AST_STRING_FIELD(lastAudioResponse);
	);
};

struct ao2_container *config;

struct gdf_config {
	int vad_voice_threshold;
	int vad_voice_minimum_duration;
	int vad_silence_minimum_duration;

	int enable_call_logs;

	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(service_key);
		AST_STRING_FIELD(endpoint);
		AST_STRING_FIELD(call_log_location);
	);
};

static struct gdf_config *gdf_get_config(void);

#ifdef ASTERISK_13_OR_LATER
typedef struct ast_format *local_ast_format_t;
#else
typedef int local_ast_format_t;
#endif

static int gdf_create(struct ast_speech *speech, local_ast_format_t format)
{
	struct gdf_pvt *pvt;
	struct gdf_config *cfg;
	char session_id[32];
	size_t sidlen = sizeof(session_id);
	char *sid = session_id;

	pvt = ast_calloc_with_stringfields(1, struct gdf_pvt, 252);
	if (!pvt) {
		ast_log(LOG_WARNING, "Error allocating memory for GDF private structure\n");
		return -1;
	}

	ast_mutex_init(&pvt->lock);

	ast_build_string(&sid, &sidlen, "%p", pvt);

	cfg = gdf_get_config();

	pvt->session = df_create_session(cfg->endpoint, cfg->service_key);

	if (!pvt->session) {
		ast_log(LOG_WARNING, "Error creating session for GDF\n");
		ao2_t_ref(cfg, -1, "done with creating session");
		ast_free(pvt);
		return -1;
	}

	/* temporarily set _something_ */
	df_set_session_id(pvt->session, session_id);
	ast_string_field_set(pvt, session_id, session_id);
	pvt->voice_threshold = cfg->vad_voice_threshold;
	pvt->voice_minimum_duration = cfg->vad_voice_minimum_duration;
	pvt->silence_minimum_duration = cfg->vad_silence_minimum_duration;

	ast_mutex_lock(&speech->lock);
	speech->state = AST_SPEECH_STATE_NOT_READY;
	speech->data = pvt;
	ast_mutex_unlock(&speech->lock);

	ao2_t_ref(cfg, -1, "done with creating session");

	return 0;
}

static int gdf_destroy(struct ast_speech *speech)
{
	struct gdf_pvt *pvt = speech->data;

	if (speech->state == AST_SPEECH_STATE_READY) {
		df_stop_recognition(pvt->session);
	}

	if (!ast_strlen_zero(pvt->lastAudioResponse)) {
		unlink(pvt->lastAudioResponse);
	}

	df_close_session(pvt->session);
	ast_string_field_free_memory(pvt);
	ast_mutex_destroy(&pvt->lock);
	return 0;
}

static int gdf_load(struct ast_speech *speech, const char *grammar_name, const char *grammar)
{
	return 0;
}

static int gdf_unload(struct ast_speech *speech, const char *grammar_name)
{
	return 0;
}

/** activate is used in this context to prime DFE with an event for 'detection'
 * 	this is typically used when starting up (e.g. event:welcome)
 */
static int gdf_activate(struct ast_speech *speech, const char *grammar_name)
{
	struct gdf_pvt *pvt = speech->data;
	if (!strncasecmp(grammar_name, "event:", 6)) {
		const char *name = grammar_name + 6;
		ast_log(LOG_DEBUG, "Activating event %s on %s\n", name, pvt->session_id);
		ast_mutex_lock(&pvt->lock);
		ast_string_field_set(pvt, event, name);
		ast_mutex_unlock(&pvt->lock);
	}
	return 0;
}

static int gdf_deactivate(struct ast_speech *speech, const char *grammar_name)
{
	return 0;
}

static int calculate_audio_level(const char *mulaw, int len)
{
	int i;
	long long sum = 0;
	for (i = 0; i < len; i++) {
		short sample = AST_MULAW((int)mulaw[i]);
		sum += abs(sample);
	}
#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	ast_log(LOG_DEBUG, "packet sum = %lld, average = %d\n", sum, (int)(sum / len));
#endif
	return sum / len;
}

/* speech structure is locked */
static int gdf_write(struct ast_speech *speech, void *data, int len)
{
	struct gdf_pvt *pvt = speech->data;
	enum dialogflow_session_state state;
	enum VAD_STATE vad_state;
	enum VAD_STATE orig_vad_state;
	int threshold;
	int cur_duration;
	int change_duration;
	int avg_level;
	int voice_duration;
	int silence_duration;
	int datams;

	ast_mutex_lock(&pvt->lock);
	orig_vad_state = vad_state = pvt->vad_state;
	threshold = pvt->voice_threshold;
	cur_duration = pvt->vad_state_duration;
	change_duration = pvt->vad_change_duration;
	voice_duration = pvt->voice_minimum_duration;
	silence_duration = pvt->silence_minimum_duration;
	ast_mutex_unlock(&pvt->lock);

	datams = len / 8; /* 8 samples per millisecond */

	cur_duration += datams;

	/* we ask for mulaw -- if we ever get slin make sure to change this */
	avg_level = calculate_audio_level((char *)data, len);
	if (avg_level >= threshold) {
		if (vad_state != VAD_STATE_SPEAK) {
			change_duration += datams;
		} else {
			change_duration = 0;
		}
	} else {
		if (vad_state != VAD_STATE_SPEAK) {
			change_duration = 0;
		} else {
			change_duration += datams;
		}
	}

	if (vad_state == VAD_STATE_START) {
		if (change_duration >= voice_duration) {
			/* speaking */
			vad_state = VAD_STATE_SPEAK;
			change_duration = 0;
			cur_duration = 0;
		}
	} else if (vad_state == VAD_STATE_SPEAK) {
		if (change_duration >= silence_duration) {
			/* stopped speaking */
			/* noop at this time */
			vad_state = VAD_STATE_SILENT;
			change_duration = 0;
			cur_duration = 0;
		}
	}

	ast_mutex_lock(&pvt->lock);
	pvt->vad_state = vad_state;
	pvt->vad_state_duration = cur_duration;
	pvt->vad_change_duration = change_duration;
	ast_mutex_unlock(&pvt->lock);

#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	ast_log(LOG_DEBUG, "avg: %d thr: %d dur: %d chg: %d vce: %d sil: %d old: %d new: %d\n",
		avg_level, threshold, cur_duration, change_duration, voice_duration, silence_duration, 
		orig_vad_state, vad_state);
#endif

	if (vad_state == VAD_STATE_SPEAK && orig_vad_state == VAD_STATE_START) {
		if (df_start_recognition(pvt->session, pvt->language)) {
			ast_log(LOG_WARNING, "Error starting recognition on %s\n", pvt->session_id);
			ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
		}
	}

	if (vad_state != VAD_STATE_START) {
		if (option_debug >= 5) {
			ast_log(LOG_DEBUG, "Writing audio to dfe\n");
		}
		state = df_write_audio(pvt->session, data, len);

		if (!ast_test_flag(speech, AST_SPEECH_QUIET) && df_get_response_count(pvt->session) > 0) {
			ast_set_flag(speech, AST_SPEECH_QUIET);
			ast_set_flag(speech, AST_SPEECH_SPOKE);
		}

		if (state == DF_STATE_FINISHED || state == DF_STATE_ERROR) {
			df_stop_recognition(pvt->session);
			ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
		}
	}

	return 0;
}

static int gdf_dtmf(struct ast_speech *speech, const char *dtmf)
{
	return -1;
}

static int gdf_start(struct ast_speech *speech)
{
	struct gdf_pvt *pvt = speech->data;
	char *event = NULL;
	char *language = NULL;

	ast_mutex_lock(&pvt->lock);
	event = ast_strdupa(pvt->event);
	language = ast_strdupa(pvt->language);
	ast_string_field_set(pvt, event, "");
	pvt->vad_state = VAD_STATE_START;
	pvt->vad_state_duration = 0;
	pvt->vad_change_duration = 0;
	ast_mutex_unlock(&pvt->lock);
	
	if (!ast_strlen_zero(event)) {
		if (df_recognize_event(pvt->session, event, language)) {
			ast_log(LOG_WARNING, "Error recognizing event on %s\n", pvt->session_id);
			ast_speech_change_state(speech, AST_SPEECH_STATE_NOT_READY);
		} else {
			ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
		}
	} else {
		ast_speech_change_state(speech, AST_SPEECH_STATE_READY);
	}

	return 0;
}

static int gdf_change(struct ast_speech *speech, const char *name, const char *value)
{
	struct gdf_pvt *pvt = speech->data;

	if (!strcasecmp(name, GDF_PROP_SESSION_ID_NAME)) {
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Session ID must have a value, refusing to set to nothing (remains %s)\n", df_get_session_id(pvt->session));
			return -1;
		}
		df_set_session_id(pvt->session, value);
		ast_mutex_lock(&pvt->lock);
		ast_string_field_set(pvt, session_id, value);
		ast_mutex_unlock(&pvt->lock);
	} else if (!strcasecmp(name, GDF_PROP_PROJECT_ID_NAME)) {
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Project ID must have a value, refusing to set to nothing (remains %s)\n", df_get_project_id(pvt->session));
			return -1;
		}
		df_set_project_id(pvt->session, value);
	} else if (!strcasecmp(name, GDF_PROP_LANGUAGE_NAME)) {
		ast_mutex_lock(&pvt->lock);
		ast_string_field_set(pvt, language, value);
		ast_mutex_unlock(&pvt->lock);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_THRESHOLD)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_VOICE_THRESHOLD " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ast_mutex_lock(&pvt->lock);
			pvt->voice_threshold = i;
			ast_mutex_unlock(&pvt->lock);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_VOICE_THRESHOLD " -- '%s'\n", value);
			return -1;
		}
	} else if (!strcasecmp(name, VAD_PROP_VOICE_DURATION)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_VOICE_DURATION " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ast_mutex_lock(&pvt->lock);
			pvt->voice_minimum_duration = i;
			ast_mutex_unlock(&pvt->lock);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_VOICE_DURATION " -- '%s'\n", value);
			return -1;
		}
	} else if (!strcasecmp(name, VAD_PROP_SILENCE_DURATION)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_SILENCE_DURATION " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ast_mutex_lock(&pvt->lock);
			pvt->silence_minimum_duration = i;
			ast_mutex_unlock(&pvt->lock);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_SILENCE_DURATION " -- '%s'\n", value);
			return -1;
		}
	} else {
		ast_log(LOG_WARNING, "Unknown property '%s'\n", name);
		return -1;
	}

	return 0;
}

#ifdef ASTERISK_13_OR_LATER
static int gdf_get_setting(struct ast_speech *speech, const char *name, char *buf, size_t len)
{
	struct gdf_pvt *pvt = speech->data;

	if (!strcasecmp(name, GDF_PROP_SESSION_ID_NAME)) {
		ast_copy_string(buf, df_get_session_id(pvt->session), len);
	} else if (!strcasecmp(name, GDF_PROP_PROJECT_ID_NAME)) {
		ast_copy_string(buf, df_get_project_id(pvt->session), len);
	} else if (!strcasecmp(name, GDF_PROP_LANGUAGE_NAME)) {
		ast_mutex_lock(&pvt->lock);
		ast_copy_string(buf, pvt->language, len);
		ast_mutex_unlock(&pvt->lock);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_THRESHOLD)) {
		ast_mutex_lock(&pvt->lock);
		ast_build_string(&buf, &len, "%d", pvt->voice_threshold);
		ast_mutex_unlock(&pvt->lock);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_DURATION)) {
		ast_mutex_lock(&pvt->lock);
		ast_build_string(&buf, &len, "%d", pvt->voice_minimum_duration);
		ast_mutex_unlock(&pvt->lock);
	} else if (!strcasecmp(name, VAD_PROP_SILENCE_DURATION)) {
		ast_mutex_lock(&pvt->lock);
		ast_build_string(&buf, &len, "%d", pvt->silence_minimum_duration);
		ast_mutex_unlock(&pvt->lock);
	} else {
		ast_log(LOG_WARNING, "Unknown property '%s'\n", name);
		return -1;
	}

	return 0;
}
#endif

static int gdf_change_results_type(struct ast_speech *speech, enum ast_speech_results_type results_type)
{
	return 0;
}

static struct ast_speech_result *gdf_get_results(struct ast_speech *speech)
{
	/* speech is not locked */
	struct gdf_pvt *pvt = speech->data;
	int results = df_get_result_count(pvt->session);
	int i;
	struct ast_speech_result *start = NULL;
	struct ast_speech_result *end = NULL;
	static int last_resort = 0;

	struct dialogflow_result *fulfillment_text = NULL;
	struct dialogflow_result *output_audio = NULL;

	const char *audioFile = NULL;

	for (i = 0; i < results; i++) {
		struct dialogflow_result *df_result = df_get_result(pvt->session, i); /* this is a borrowed reference */
		if (df_result) {
			if (!strcasecmp(df_result->slot, "output_audio")) {
				/* this is fine for now, but we really need a flag on the structure that says it's binary vs. text */
				output_audio = df_result;
			} else {
				struct ast_speech_result *new = ast_calloc(1, sizeof(*new));
				if (new) {
					new->text = ast_strdup(df_result->value);
					new->score = df_result->score;
					new->grammar = ast_strdup(df_result->slot);

					if (!strcasecmp(df_result->slot, "fulfillment_text")) {
						fulfillment_text = df_result;
					}
				}

				if (end) {
					AST_LIST_NEXT(end, list) = new;
					end = new;
				} else {
					start = end = new;
				}
			}
		}
	}

	if (output_audio) { 
		struct ast_speech_result *new;
		char tmpFilename[128];
		int fd;
		ssize_t written;

		ast_copy_string(tmpFilename, "/tmp/res_speech_gdfe_fulfillment_XXXXXX.wav", sizeof(tmpFilename));
		fd = mkstemps(tmpFilename, 4);

		if (fd < 0) {
			ast_log(LOG_WARNING, "Unable to create temporary file for fulfillment message\n");
			sprintf(tmpFilename, "/tmp/res_speech_gdfe_fulfillment_%d.wav", ast_atomic_fetchadd_int(&last_resort, 1));
			fd = open(tmpFilename, O_WRONLY | O_CREAT, 0600);
		}
		written = write(fd, output_audio->value, output_audio->valueLen);
		if (written < output_audio->valueLen) {
			ast_log(LOG_WARNING, "Short write to temporary file for fulfillment message\n");
		}
		close(fd);

		audioFile = tmpFilename;

		new = ast_calloc(1, sizeof(*new));
		if (new) {
			new->text = ast_strdup(tmpFilename);
			new->score = 100;
			new->grammar = ast_strdup("fulfillment_audio");

			if (end) {
				AST_LIST_NEXT(end, list) = new;
				end = new;
			} else {
				start = end = new;
			}
		} else {
			ast_log(LOG_WARNING, "Unable to allocate speech result slot for synthesized fulfillment text\n");
		}
	} else if (fulfillment_text && !ast_strlen_zero(fulfillment_text->value)) {
		char tmpFilename[128];
		int fd;
		struct gdf_config *cfg;
		char *key;
		char *language;

		cfg = gdf_get_config();
		key = ast_strdupa(cfg->service_key);
		ao2_t_ref(cfg, -1, "done with creating session");

		ast_mutex_lock(&pvt->lock);
		language = ast_strdupa(pvt->language);
		ast_mutex_unlock(&pvt->lock);

		ast_copy_string(tmpFilename, "/tmp/res_speech_gdfe_fulfillment_XXXXXX.wav", sizeof(tmpFilename));
		fd = mkstemps(tmpFilename, 4);

		if (fd >= 0) {
			close(fd);
		} else {
			ast_log(LOG_WARNING, "Unable to create temporary file for fulfillment message\n");
			sprintf(tmpFilename, "/tmp/res_speech_gdfe_fulfillment_%d.wav", ast_atomic_fetchadd_int(&last_resort, 1));
		}

		audioFile = tmpFilename;

		if (google_synth_speech(NULL, key, fulfillment_text->value, language, NULL, tmpFilename)) {
			ast_log(LOG_WARNING, "Failed to synthesize fulfillment text to %s\n", tmpFilename);
		} else {
			struct ast_speech_result *new = ast_calloc(1, sizeof(*new));
			if (new) {
				new->text = ast_strdup(tmpFilename);
				new->score = 100;
				new->grammar = ast_strdup("fulfillment_audio");

				if (end) {
					AST_LIST_NEXT(end, list) = new;
					end = new;
				} else {
					start = end = new;
				}
			} else {
				ast_log(LOG_WARNING, "Unable to allocate speech result slot for synthesized fulfillment text\n");
			}
		}
	}

	if (!ast_strlen_zero(audioFile)) {
		if (!ast_strlen_zero(pvt->lastAudioResponse)) {
			unlink(pvt->lastAudioResponse);
		}
		ast_string_field_set(pvt, lastAudioResponse, audioFile);
	}

	return start;
}

static void gdf_config_destroy(void *o)
{
	struct gdf_config *conf = o;

	ast_string_field_free_memory(conf);
}

static struct gdf_config *gdf_get_config(void)
{
	struct gdf_config *cfg;
#ifdef ASTERISK_13_OR_LATER
	ao2_rdlock(config);
#else
	ao2_lock(config);
#endif
	cfg = ao2_find(config, NULL, 0);
	ao2_unlock(config);
	return cfg;
}

#define CONFIGURATION_FILENAME		"res_speech_gdfe.conf"
static int load_config(int reload)
{
	struct ast_config *cfg = NULL;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	cfg = ast_config_load(CONFIGURATION_FILENAME, config_flags);
	if (cfg == CONFIG_STATUS_FILEUNCHANGED) {
		ast_log(LOG_DEBUG, "Configuration unchanged.\n");
	} else {
		struct gdf_config *conf;
		const char *val;

		if (cfg == CONFIG_STATUS_FILEINVALID) {
			ast_log(LOG_WARNING, "Configuration file invalid\n");
			cfg = ast_config_new();
		} else if (cfg == CONFIG_STATUS_FILEMISSING) {
			ast_log(LOG_WARNING, "Configuration not found, using defaults\n");
			cfg = ast_config_new();
		}
		
		conf = ao2_alloc(sizeof(*conf), gdf_config_destroy);
		if (!conf) {
			ast_log(LOG_WARNING, "Failed to allocate config record for speech gdf\n");
			ast_config_destroy(cfg);
			return AST_MODULE_LOAD_FAILURE;
		}

		if (ast_string_field_init(conf, 3 * 1024)) {
			ast_log(LOG_WARNING, "Failed to allocate string fields for config for speech gdf\n");
			ao2_ref(conf, -1);
			ast_config_destroy(cfg);
			return AST_MODULE_LOAD_FAILURE;
		}

		val = ast_variable_retrieve(cfg, "general", "service_key");
		if (ast_strlen_zero(val)) {
			ast_log(LOG_VERBOSE, "Service key not provided -- will use default credentials.\n");
		} else if (strchr(val, '{')) {
			ast_log(LOG_DEBUG, "service_key in configuration detected as an actual key\n");
			ast_string_field_set(conf, service_key, val);
		} else {
			FILE *f;
			ast_log(LOG_DEBUG, "Loading service key data from %s\n", val);
			f = fopen(val, "r");
			if (f) {
				struct ast_str *buffer = ast_str_create(3 * 1024); /* big enough for the typical key size */
				if (buffer) {
					char readbuffer[512];
					size_t read = fread(readbuffer, sizeof(char), sizeof(readbuffer), f);
					while (read > 0) {
						ast_str_append_substr(&buffer, -1, readbuffer, read);
						read = fread(readbuffer, sizeof(char), sizeof(readbuffer), f);
					}
					if (ferror(f)) {
						ast_log(LOG_WARNING, "Error reading %s -- %d\n", val, errno);
					}
					fclose(f);
					ast_string_field_set(conf, service_key, ast_str_buffer(buffer));
					ast_free(buffer);
				} else {
					ast_log(LOG_WARNING, "Unable to load key from %s -- buffer allocation error\n", val);
				}
			} else {
				ast_log(LOG_ERROR, "Unable to open service key file %s -- %d\n", val, errno);
			}
		}

		val = ast_variable_retrieve(cfg, "general", "endpoint");
		if (!ast_strlen_zero(val)) {
			ast_string_field_set(conf, endpoint, val);
		}

		conf->vad_voice_threshold = 512;
		val = ast_variable_retrieve(cfg, "general", "vad_voice_threshold");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				conf->vad_voice_threshold = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_voice_threshold\n");
			}
		}

		conf->vad_voice_minimum_duration = 40; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_voice_minimum_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				conf->vad_voice_minimum_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_voice_minimum_duration\n");
			}
		}

		conf->vad_silence_minimum_duration = 500; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_silence_minimum_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				conf->vad_silence_minimum_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_silence_minimum_duration\n");
			}
		}

		ast_string_field_set(conf, call_log_location, "/var/log/dialogflow/${CONTEXT}/${STRFTIME(,,%%Y/%%m/%%d/%%H)}/");
		val = ast_variable_retrieve(cfg, "general", "call_log_location");
		if (!ast_strlen_zero(val)) {
			ast_string_field_set(conf, call_log_location, val);
		}

		/* swap out the configs */
#ifdef ASTERISK_13_OR_LATER
		ao2_wrlock(config);
#else
		ao2_lock(config);
#endif
		{
			struct gdf_config *old_config = gdf_get_config();
			ao2_unlink(config, old_config);
			ao2_ref(old_config, -1);
		}
		ao2_link(config, conf);
		ao2_unlock(config);
		ao2_ref(conf, -1);
	}

	if (cfg) {
		ast_config_destroy(cfg);
	}
	
	return AST_MODULE_LOAD_SUCCESS;
}

static char *gdfe_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "gdfe reload";
		e->usage = 
			"Usage: gdfe reload\n"
			"       Reload res_speech_gdfe configuration.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	default:
		ast_cli(a->fd, "Reloading res_speech_gdfe config from " CONFIGURATION_FILENAME "\n");
		load_config(1);
		ast_cli(a->fd, "Reload complete\n");
		ast_cli(a->fd, "\n\n");
		return CLI_SUCCESS;
	}
}

static char *gdfe_show_config(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct gdf_config *config;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "gdfe show config";
		e->usage = 
			"Usage: gdfe show config\n"
			"       Show current gdfe configuration.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	default:
		config = gdf_get_config();
		if (config) {
			ast_cli(a->fd, "[general]\n");
			ast_cli(a->fd, "service_key = %s\n", config->service_key);
			ast_cli(a->fd, "endpoint = %s\n", config->endpoint);
			ast_cli(a->fd, "vad_voice_threshold = %d\n", config->vad_voice_threshold);
			ast_cli(a->fd, "vad_voice_minimum_duration = %d\n", config->vad_voice_minimum_duration);
			ast_cli(a->fd, "vad_silence_minimum_duration = %d\n", config->vad_silence_minimum_duration);
			ast_cli(a->fd, "enable_call_logs = %s\n", AST_CLI_YESNO(config->enable_call_logs));
			ast_cli(a->fd, "call_log_location = %s\n", config->call_log_location);
			ao2_ref(config, -1);
		} else {
			ast_cli(a->fd, "Unable to retrieve configuration\n");
		}
		ast_cli(a->fd, "\n");
		return CLI_SUCCESS;
	}
}

static struct ast_cli_entry gdfe_cli[] = {
	AST_CLI_DEFINE(gdfe_reload, "Reload gdfe configuration"),
	AST_CLI_DEFINE(gdfe_show_config, "Show current gdfe configuration"),
};


static void gdf_log(enum dialogflow_log_level level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	char *buff;
	va_list args2;
	va_copy(args2, args);
    size_t len = vsnprintf(NULL, 0, fmt, args2);
    va_end(args2);
    buff = alloca(len + 1);
    vsnprintf(buff, len + 1, fmt, args);

	ast_log((int) level, file, line, function, "%s", buff);
}

static char gdf_engine_name[] = "GoogleDFE";

static struct ast_speech_engine gdf_engine = {
	.name = gdf_engine_name,
	.create = gdf_create,
	.destroy = gdf_destroy,
	.load = gdf_load,
	.unload = gdf_unload,
	.activate = gdf_activate,
	.deactivate = gdf_deactivate,
	.write = gdf_write,
	.dtmf = gdf_dtmf,
	.start = gdf_start,
	.change = gdf_change,
#ifdef ASTERISK_13_OR_LATER
	.get_setting = gdf_get_setting,
#endif
	.change_results_type = gdf_change_results_type,
	.get = gdf_get_results
};

static enum ast_module_load_result load_module(void)
{
	struct gdf_config *cfg;

	config = ao2_container_alloc(1, NULL, NULL);
	if (!config) {
		ast_log(LOG_ERROR, "Failed to allocate configuration container\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	cfg = ao2_alloc(sizeof(*cfg), gdf_config_destroy);
	if (!cfg) {
		ast_log(LOG_ERROR, "Failed to allocate blank configuration\n");
		ao2_ref(config, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	ao2_link(config, cfg);
	ao2_ref(cfg, -1);

	if (load_config(0)) {
		ast_log(LOG_WARNING, "Failed to load configuration\n");
	}

#ifdef ASTERISK_13_OR_LATER
	gdf_engine.formats = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);

	if (!gdf_engine.formats) {
		ast_log(LOG_ERROR, "DFE speech could not create format caps\n");
		ao2_ref(config, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	ast_format_cap_append(gdf_engine.formats, ast_format_ulaw, 20);
#else
	gdf_engine.formats = AST_FORMAT_ULAW;
#endif

	if (ast_speech_register(&gdf_engine)) {
		ast_log(LOG_WARNING, "DFE speech failed to register with speech subsystem\n");
		ao2_ref(config, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	if (df_init(gdf_log)) {
		ast_log(LOG_WARNING, "Failed to initialize dialogflow library\n");
		ao2_ref(config, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	ast_cli_register_multiple(gdfe_cli, ARRAY_LEN(gdfe_cli));

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	if (ast_speech_unregister(gdf_engine.name)) {
		ast_log(LOG_WARNING, "Failed to unregister GDF speech engine\n");
		return -1;
	}

	ast_cli_unregister_multiple(gdfe_cli, ARRAY_LEN(gdfe_cli));

#ifdef ASTERISK_13_OR_LATER
	ao2_t_ref(gdf_engine.formats, -1, "unloading module");
#endif

	return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Google DialogFlow for Enterprise (DFE) Speech Engine");