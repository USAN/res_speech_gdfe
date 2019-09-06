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

//#define REF_DEBUG 1

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
#ifndef AST_SPEECH_HAVE_GET_SETTING
#define AST_SPEECH_HAVE_GET_SETTING
#endif
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

#include <asterisk/chanvars.h>
#include <asterisk/pbx.h>
#include <asterisk/config.h>
#include <asterisk/ulaw.h>

#include <libdfegrpc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef ASTERISK_13_OR_LATER
#include <jansson.h>
#endif

#define GDF_PROP_SESSION_ID_NAME	"session_id"
#define GDF_PROP_ALTERNATE_SESSION_NAME "name"
#define GDF_PROP_PROJECT_ID_NAME	"project_id"
#define GDF_PROP_LANGUAGE_NAME		"language"
#define GDF_PROP_LOG_CONTEXT		"log_context"
#define GDF_PROP_ALTERNATE_LOG_CONTEXT	"logContext"
#define GDF_PROP_APPLICATION_CONTEXT	"application"
#define GDF_PROP_REQUEST_SENTIMENT_ANALYSIS "request_sentiment_analysis"
#define VAD_PROP_VOICE_THRESHOLD	"voice_threshold"
#define VAD_PROP_VOICE_DURATION		"voice_duration"
#define VAD_PROP_SILENCE_DURATION	"silence_duration"
#define VAD_PROP_BARGE_DURATION		"barge_duration"
#define VAD_PROP_END_OF_SPEECH_DURATION	"end_of_speech_duration"

#define GDF_PROP_UTTERANCE_DURATION_MS	"utterance_duration_ms"

typedef int milliseconds_t;

enum VAD_STATE {
	VAD_STATE_START,
	VAD_STATE_SPEAK,
	VAD_STATE_SILENT,
	VAD_STATE_END,
};

enum SENTIMENT_ANALYSIS_STATE {
	SENTIMENT_ANALYSIS_DEFAULT,
	SENTIMENT_ANALYSIS_NEVER,
	SENTIMENT_ANALYSIS_ALWAYS
};

enum GDFE_STATE {
	GDFE_STATE_START,
	GDFE_STATE_PROCESSING,
	GDFE_STATE_HAVE_RESULTS,
	GDFE_STATE_DONE
};

struct gdf_request;

struct gdf_pvt {
	struct ast_speech *speech;
	
	milliseconds_t vad_state_duration;
	milliseconds_t vad_change_duration; /* cumulative time of "not current state" audio */

	int voice_threshold; /* 0 - (2^16 - 1) */
	milliseconds_t voice_minimum_duration;
	milliseconds_t silence_minimum_duration;
	milliseconds_t barge_in_minimum_duration;
	milliseconds_t end_of_speech_minimum_silence;

	milliseconds_t incomplete_timeout;
	milliseconds_t no_speech_timeout;
	milliseconds_t maximum_speech_timeout;

	int call_log_open_already_attempted;
	FILE *call_log_file_handle;

	int utterance_counter;
	struct gdf_request *current_request;

	enum SENTIMENT_ANALYSIS_STATE effective_sentiment_analysis_state;
	int request_sentiment_analysis;
	int use_internal_endpointer_for_end_of_speech;

	int record_next_utterance;

	struct timeval session_start; /* log only, no store duration */

	char **hints;
	size_t hint_count;

	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(logical_agent_name);
		AST_STRING_FIELD(project_id);
		AST_STRING_FIELD(session_id);
		AST_STRING_FIELD(service_key);
		AST_STRING_FIELD(endpoint);
		AST_STRING_FIELD(event);
		AST_STRING_FIELD(language);
		AST_STRING_FIELD(lastAudioResponse);
		AST_STRING_FIELD(model);

		AST_STRING_FIELD(call_log_path);
		AST_STRING_FIELD(call_log_file_basename);
		AST_STRING_FIELD(call_logging_application_name);
		AST_STRING_FIELD(call_logging_context);
	);
};

struct gdf_request {
	struct gdf_pvt *pvt;
	struct dialogflow_session *session;
	
	int current_utterance_number;
	int current_start_retry;

	enum VAD_STATE vad_state;
	milliseconds_t vad_state_duration;
	milliseconds_t vad_change_duration; /* cumulative time of "not current state" audio */

	int voice_threshold; /* 0 - (2^16 - 1) */
	int heard_speech;
	milliseconds_t voice_minimum_duration;
	milliseconds_t silence_minimum_duration;
	milliseconds_t barge_in_minimum_duration;
	milliseconds_t end_of_speech_minimum_silence;

	milliseconds_t incomplete_timeout;
	milliseconds_t no_speech_timeout;
	milliseconds_t maximum_speech_timeout;

	int record_utterance;

	int utterance_preendpointer_recording_open_already_attempted;
	FILE *utterance_preendpointer_recording_file_handle;
	int utterance_postendpointer_recording_open_already_attempted;
	FILE *utterance_postendpointer_recording_file_handle;

	char *mulaw_endpointer_audio_cache;
	size_t mulaw_endpointer_audio_cache_size;
	size_t mulaw_endpointer_audio_cache_start;
	size_t mulaw_endpointer_audio_cache_len;

	struct timeval session_start; /* log only, no store duration */
	struct timeval endpointer_end_of_speech_time;
	struct timeval request_start;
	struct timeval recognition_initial_attempt;
	struct timeval speech_start;
	struct timeval endpointer_barge_in_time;
	struct timeval dialogflow_barge_in_time;
	long long last_request_duration_ms;
	long long last_audio_duration_ms; /* calculated by packet, not clock */

	pthread_t thread;
	enum GDFE_STATE state;
	AST_LIST_HEAD_NOLOCK(, ast_frame) frame_queue;
	int frame_queue_len;

	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(project_id);
		AST_STRING_FIELD(service_key);
		AST_STRING_FIELD(endpoint);
		AST_STRING_FIELD(event);
		AST_STRING_FIELD(language);
		AST_STRING_FIELD(pre_recording_filename);
		AST_STRING_FIELD(post_recording_filename);
		AST_STRING_FIELD(model);
	);
};

struct ao2_container *config;

struct gdf_logical_agent {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(name);
		AST_STRING_FIELD(project_id);
		AST_STRING_FIELD(service_key);
		AST_STRING_FIELD(endpoint);
		AST_STRING_FIELD(model);
	);
	enum SENTIMENT_ANALYSIS_STATE enable_sentiment_analysis;
	int use_internal_endpointer_for_end_of_speech;
	struct ao2_container *hints;
};

struct gdf_config {
	int vad_voice_threshold;
	milliseconds_t vad_voice_minimum_duration;
	milliseconds_t vad_silence_minimum_duration;
	milliseconds_t vad_barge_minimum_duration;
	milliseconds_t vad_end_of_speech_silence_duration;

	milliseconds_t endpointer_cache_audio_pretrigger_ms;

	milliseconds_t default_incomplete_timeout;
	milliseconds_t default_no_speech_timeout;
	milliseconds_t default_maximum_speech_timeout;

	int enable_call_logs;
	int enable_preendpointer_recordings;
	int enable_postendpointer_recordings;
	int record_preendpointer_on_demand;
	int use_internal_endpointer_for_end_of_speech;
	enum SENTIMENT_ANALYSIS_STATE enable_sentiment_analysis;

	int stop_writes_on_final_transcription;
	int start_recognition_on_start; /* vs. on speech */
	int recognition_start_failure_retries;
	int recognition_start_failure_retry_max_time_ms;

	struct ao2_container *logical_agents;
	struct ao2_container *hints;

	int synthesize_fulfillment_text;

	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(service_key);
		AST_STRING_FIELD(endpoint);
		AST_STRING_FIELD(call_log_location);
		AST_STRING_FIELD(start_failure_retry_codes);
		AST_STRING_FIELD(model);
	);
};

enum gdf_call_log_type {
	CALL_LOG_TYPE_SESSION,
	CALL_LOG_TYPE_RECOGNITION,
	CALL_LOG_TYPE_ENDPOINTER,
	CALL_LOG_TYPE_DIALOGFLOW
};

static struct gdf_config *gdf_get_config(void);
static struct gdf_logical_agent *get_logical_agent_by_name(struct gdf_config *config, const char *name);
static void gdf_log_call_event(struct gdf_pvt *pvt, struct gdf_request *req, enum gdf_call_log_type type, const char *event, size_t log_data_size, const struct dialogflow_log_data *log_data);
#define gdf_log_call_event_only(pvt, req, type, event)       gdf_log_call_event(pvt, req, type, event, 0, NULL)

static struct ast_str *build_log_related_filename_to_thread_local_str(struct gdf_pvt *pvt, struct gdf_request *req, const char *type, const char *extension);

static void *gdf_exec(void *arg);

#ifdef ASTERISK_13_OR_LATER
typedef struct ast_format *local_ast_format_t;
#else
typedef int local_ast_format_t;
#endif

static void gdf_request_destructor(void *obj)
{
	struct gdf_request *req = obj;
	struct ast_frame *f;

	ast_log(LOG_DEBUG, "Destroying gdf request %d@%s\n", req->current_utterance_number, req->pvt->session_id);

	df_close_session(req->session);

	if (req->mulaw_endpointer_audio_cache) {
		ast_free(req->mulaw_endpointer_audio_cache);
		req->mulaw_endpointer_audio_cache = NULL;
	}

	while ((f = AST_LIST_REMOVE_HEAD(&req->frame_queue, frame_list))) {
		ast_frfree(f);
	}

	ast_string_field_free_memory(req);

	if (req->pvt) {
		ao2_t_ref(req->pvt, -1, "Destroying request");
		req->pvt = NULL;
	}
}

static void gdf_pvt_destructor(void *obj)
{
	struct gdf_pvt *pvt = obj;

	ast_log(LOG_DEBUG, "Destroying gdf pvt %s\n", pvt->session_id);

	if (pvt->call_log_file_handle != NULL) {
		fclose(pvt->call_log_file_handle);
	}

	if (pvt->hints) {
		size_t i;
		for (i = 0; i < pvt->hint_count; i++) {
			ast_free(pvt->hints[i]);
		}
		ast_free(pvt->hints);
	}

	if (!ast_strlen_zero(pvt->lastAudioResponse)) {
		unlink(pvt->lastAudioResponse);
		ast_string_field_set(pvt, lastAudioResponse, "");
	}

	ast_string_field_free_memory(pvt);
}

static int gdf_create(struct ast_speech *speech, local_ast_format_t format)
{
	struct gdf_pvt *pvt;
	struct gdf_config *cfg;
	char session_id[32];
	size_t sidlen = sizeof(session_id);
	char *sid = session_id;

	pvt = ao2_alloc(sizeof(struct gdf_pvt), gdf_pvt_destructor);
	if (!pvt) {
		ast_log(LOG_WARNING, "Error allocating memory for GDF private structure\n");
		return -1;
	}

	if (ast_string_field_init(pvt, 252)) {
		ast_log(LOG_WARNING, "Error allocating GDF private string fields\n");
		ao2_t_ref(pvt, -1, "Error allocating string fields");
		return -1;
	}

	ast_build_string(&sid, &sidlen, "%p", pvt);

	cfg = gdf_get_config();

	ast_string_field_set(pvt, session_id, session_id);
	pvt->voice_threshold = cfg->vad_voice_threshold;
	pvt->voice_minimum_duration = cfg->vad_voice_minimum_duration;
	pvt->silence_minimum_duration = cfg->vad_silence_minimum_duration;
	pvt->barge_in_minimum_duration = cfg->vad_barge_minimum_duration;
	pvt->end_of_speech_minimum_silence = cfg->vad_end_of_speech_silence_duration;
	pvt->session_start = ast_tvnow();
	pvt->incomplete_timeout = cfg->default_incomplete_timeout;
	pvt->no_speech_timeout = cfg->default_no_speech_timeout;
	pvt->maximum_speech_timeout = cfg->default_maximum_speech_timeout;
	ast_string_field_set(pvt, call_logging_application_name, "unknown");
	pvt->speech = speech;

	ast_log(LOG_DEBUG, "Creating GDF session %s\n", pvt->session_id);

	ast_mutex_lock(&speech->lock);
	speech->state = AST_SPEECH_STATE_NOT_READY;
	speech->data = pvt;
	/* speech will borrow this reference */
	ast_mutex_unlock(&speech->lock);

	ao2_t_ref(cfg, -1, "done with creating session");

	return 0;
}

static void reset_pvt_timeouts_to_defaults_on_new_request(struct gdf_pvt *pvt_locked, struct gdf_config *cfg)
{
	pvt_locked->incomplete_timeout = cfg->default_incomplete_timeout;
	pvt_locked->no_speech_timeout = cfg->default_no_speech_timeout;
	pvt_locked->maximum_speech_timeout = cfg->default_maximum_speech_timeout;
}

static struct gdf_request *create_new_request(struct gdf_pvt *pvt_locked, int utterance_number)
{
	struct gdf_request *req;
	struct gdf_config *cfg;
	int res;

	req = ao2_alloc(sizeof(struct gdf_request), gdf_request_destructor);
	if (!req) {
		ast_log(LOG_WARNING, "Error allocating memory for GDF request structure\n");
		return NULL;
	}

	if (ast_string_field_init(req, 252)) {
		ast_log(LOG_WARNING, "Error allocating GDF request string fields\n");
		ao2_t_ref(req, -1, "Error allocating string fields");
		return NULL;
	}

	ao2_t_ref(pvt_locked, 1, "Adding backpointer from request to private");
	req->pvt = pvt_locked;
	req->current_utterance_number = utterance_number;

	cfg = gdf_get_config();

	req->session = df_create_session(req);
	if (!req->session) {
		ast_log(LOG_WARNING, "Error creating session for GDF\n");
		ao2_t_ref(cfg, -1, "done with creating request");
		ao2_t_ref(req, -1, "Error creating dialogflow request");
		return NULL;
	}
	df_set_auth_key(req->session, pvt_locked->service_key);
	df_set_endpoint(req->session, pvt_locked->endpoint);
	df_set_session_id(req->session, pvt_locked->session_id);
	df_set_stop_writes_on_final_transcription(req->session, cfg->stop_writes_on_final_transcription);

	ast_string_field_set(req, project_id, pvt_locked->project_id);
	ast_string_field_set(req, event, pvt_locked->event);
	ast_string_field_set(req, language, pvt_locked->language);
	ast_string_field_set(req, service_key, pvt_locked->service_key);
	ast_string_field_set(req, endpoint, pvt_locked->endpoint);
	ast_string_field_set(req, model, pvt_locked->model);

	req->voice_threshold = pvt_locked->voice_threshold;
	req->voice_minimum_duration = pvt_locked->voice_minimum_duration;
	req->silence_minimum_duration = pvt_locked->silence_minimum_duration;
	req->barge_in_minimum_duration = pvt_locked->barge_in_minimum_duration;
	req->end_of_speech_minimum_silence = pvt_locked->end_of_speech_minimum_silence;
	req->session_start = ast_tvnow();
	req->last_audio_duration_ms = 0;
	req->incomplete_timeout = pvt_locked->incomplete_timeout;
	req->no_speech_timeout = pvt_locked->no_speech_timeout;
	req->maximum_speech_timeout = pvt_locked->maximum_speech_timeout;
	reset_pvt_timeouts_to_defaults_on_new_request(pvt_locked, cfg);

	if (req->voice_minimum_duration || cfg->endpointer_cache_audio_pretrigger_ms) {
		size_t cache_needed_size = (req->voice_minimum_duration + cfg->endpointer_cache_audio_pretrigger_ms) * 8; /* bytes per millisecond */
		req->mulaw_endpointer_audio_cache = ast_calloc(1, cache_needed_size);
		if (req->mulaw_endpointer_audio_cache) {
			req->mulaw_endpointer_audio_cache_size = cache_needed_size;
			req->mulaw_endpointer_audio_cache_start = 0;
			req->mulaw_endpointer_audio_cache_len = 0;
		}
	}

	ast_log(LOG_DEBUG, "Creating GDF request %d@%s\n", req->current_utterance_number, pvt_locked->session_id);

	ast_speech_change_state(pvt_locked->speech, AST_SPEECH_STATE_READY);

	ao2_t_ref(req, 1, "Bump ref for background thread");
	res = ast_pthread_create_detached(&req->thread, NULL, gdf_exec, req);
	if (res) {
		ast_log(LOG_WARNING, "Unable to create background thread for GDF");
		ao2_t_ref(cfg, -1, "done with creating request");
		ao2_t_ref(req, -1, "Error creating background thread");
		return NULL;
	}

	ao2_t_ref(cfg, -1, "done with creating request");

	return req;
}

static void log_session_end(struct gdf_pvt *pvt, long long duration_ms)
{
	char duration_buffer[20] = "";
	char *buff = duration_buffer;
	size_t buffLen = sizeof(duration_buffer);
	struct dialogflow_log_data log_data[] = {
		{ "duration_ms", duration_buffer }
	};

	ast_build_string(&buff, &buffLen, "%lld", duration_ms);

	gdf_log_call_event(pvt, NULL, CALL_LOG_TYPE_SESSION, "end", ARRAY_LEN(log_data), log_data);
}

static int gdf_destroy(struct ast_speech *speech)
{
	struct gdf_pvt *pvt = speech->data;

	ao2_lock(pvt);
	pvt->speech = NULL;
	if (pvt->current_request) {
		ao2_t_ref(pvt->current_request, -1, "Destroying session, releasing request");
	}
	pvt->current_request = NULL;
	ao2_unlock(pvt);
	
	log_session_end(pvt, ast_tvdiff_ms(ast_tvnow(), pvt->session_start));

	ast_log(LOG_DEBUG, "Destroying GDF %s\n", pvt->session_id);
	ao2_t_ref(pvt, -1, "Destroying speech session");
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

#define EVENT_COLON_LEN	6
#define EVENT_COLON		"event:"
static int is_grammar_old_style_event(const char *grammar_name)
{
	return !strncasecmp(grammar_name, EVENT_COLON, EVENT_COLON_LEN);
}

static void activate_old_style_event(struct gdf_pvt *pvt, const char *grammar_name)
{
	const char *name = grammar_name + EVENT_COLON_LEN;
	ast_log(LOG_DEBUG, "Activating event %s on %s\n", name, pvt->session_id);
	ao2_lock(pvt);
	ast_string_field_set(pvt, event, name);
	ao2_unlock(pvt);
}

#define BUILTIN_COLON_GRAMMAR_SLASH_LEN	16
#define BUILTIN_COLON_GRAMMAR_SLASH		"builtin:grammar/"
static int is_grammar_new_style_format(const char *grammar_name)
{
	return !strncasecmp(grammar_name, BUILTIN_COLON_GRAMMAR_SLASH, BUILTIN_COLON_GRAMMAR_SLASH_LEN);
}

static void calculate_effective_sentiment_analysis_state(struct gdf_pvt *pvt_locked, struct gdf_config *config, struct gdf_logical_agent *logical_agent)
{
	pvt_locked->effective_sentiment_analysis_state = SENTIMENT_ANALYSIS_DEFAULT;
	if (config && config->enable_sentiment_analysis != SENTIMENT_ANALYSIS_DEFAULT) {
		pvt_locked->effective_sentiment_analysis_state = config->enable_sentiment_analysis;
	} else if (logical_agent) {
		pvt_locked->effective_sentiment_analysis_state = logical_agent->enable_sentiment_analysis;
	}
}

static void calculate_effective_hints(struct gdf_pvt *pvt_locked, struct gdf_config *config, struct gdf_logical_agent *logical_agent)
{
	struct ao2_container *hint_container = NULL;

	if (pvt_locked->hints) {
		size_t i;
		for (i = 0; i < pvt_locked->hint_count; i++) {
			ast_free(pvt_locked->hints[i]);
		}
		ast_free(pvt_locked->hints);
		pvt_locked->hints = NULL;
	}

	pvt_locked->hint_count = 0;

	if (logical_agent) {
		hint_container = logical_agent->hints;
	}
	if (hint_container == NULL || !ao2_container_count(hint_container)) {
		hint_container = config->hints;
	}

	if (hint_container) {
		size_t hint_count = ao2_container_count(hint_container);
		if (hint_count > 0) {
			pvt_locked->hints = ast_calloc(hint_count, sizeof(char *));
			if (pvt_locked->hints) {
				size_t i;
				struct ao2_iterator hint_iterator;
				char *entry;

				hint_iterator = ao2_iterator_init(hint_container, 0);
				for (i = 0, entry = ao2_iterator_next(&hint_iterator); entry && i < hint_count; i++, entry = ao2_iterator_next(&hint_iterator)) {
					pvt_locked->hints[i] = ast_strdup(entry);
					pvt_locked->hint_count = i + 1;
					ao2_ref(entry, -1);
				}
				ao2_iterator_destroy(&hint_iterator);
			}
		}
	}
}

static void activate_agent_for_name(struct gdf_pvt *pvt, const char *name, size_t name_len, const char *event)
{
	struct gdf_config *config;

	ao2_lock(pvt);
	ast_string_field_build(pvt, logical_agent_name, "%.*s", (int) name_len, name);
	ast_string_field_set(pvt, event, event);
	ao2_unlock(pvt);

	config = gdf_get_config();
	if (config) {
		struct gdf_logical_agent *logical_agent_map = get_logical_agent_by_name(config, pvt->logical_agent_name);
		ao2_lock(pvt);
		ast_string_field_set(pvt, project_id, S_OR(logical_agent_map ? logical_agent_map->project_id : NULL, pvt->logical_agent_name));
		ast_string_field_set(pvt, service_key, S_OR(logical_agent_map ? logical_agent_map->service_key : NULL, config->service_key));
		ast_string_field_set(pvt, endpoint, S_OR(logical_agent_map ? logical_agent_map->endpoint : NULL, config->endpoint));
		ast_string_field_set(pvt, model, S_OR(logical_agent_map ? logical_agent_map->model : NULL, config->model));
		calculate_effective_sentiment_analysis_state(pvt, config, logical_agent_map);
		calculate_effective_hints(pvt, config, logical_agent_map);
		pvt->use_internal_endpointer_for_end_of_speech = logical_agent_map ? logical_agent_map->use_internal_endpointer_for_end_of_speech : config->use_internal_endpointer_for_end_of_speech;
		ao2_unlock(pvt);
		if (logical_agent_map) {
			ao2_ref(logical_agent_map, -1);
		}
		ao2_ref(config, -1);
	} else {
		ao2_lock(pvt);
		ast_string_field_set(pvt, project_id, pvt->logical_agent_name);
		ast_string_field_set(pvt, model, "");
		calculate_effective_sentiment_analysis_state(pvt, NULL, NULL);
		pvt->use_internal_endpointer_for_end_of_speech = 1;
		ao2_unlock(pvt);
	}

	if (!ast_strlen_zero(event)) {
		ast_log(LOG_DEBUG, "Activating project %s ('%s'), event %s on %s\n", 
			pvt->project_id, pvt->logical_agent_name, pvt->event, pvt->session_id);
	} else {
		ast_log(LOG_DEBUG, "Activating project %s ('%s') on %s\n", pvt->project_id, pvt->logical_agent_name,
			pvt->session_id);
	}
}

static void activate_new_style_grammar(struct gdf_pvt *pvt, const char *grammar_name)
{
	const char *name_part = grammar_name + BUILTIN_COLON_GRAMMAR_SLASH_LEN;
	const char *event_part = "";
	size_t name_len;
	const char *question_mark;

	if ((question_mark = strchr(name_part, '?'))) {
		name_len = question_mark - name_part;
		event_part = question_mark + 1;
	} else {
		name_len = strlen(name_part);
	}

	activate_agent_for_name(pvt, name_part, name_len, event_part);
}

/** activate is used in this context to prime DFE with an event for 'detection'
 * 	this is typically used when starting up (e.g. event:welcome)
 */
static int gdf_activate(struct ast_speech *speech, const char *grammar_name)
{
	struct gdf_pvt *pvt = speech->data;
	if (is_grammar_old_style_event(grammar_name)) {
		activate_old_style_event(pvt, grammar_name);
	} else if (is_grammar_new_style_format(grammar_name)) {
		activate_new_style_grammar(pvt, grammar_name);
	} else {
		ast_log(LOG_WARNING, "Do not understand grammar name %s on %s\n", grammar_name, pvt->session_id);
		return -1;
	}
	return 0;
}

static int gdf_deactivate(struct ast_speech *speech, const char *grammar_name)
{
	return 0;
}

static int calculate_audio_level(const short *slin, int len)
{
	int i;
	long long sum = 0;
	for (i = 0; i < len; i++) {
		short sample = slin[i];
		sum += abs(sample);
	}
#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	ast_log(LOG_DEBUG, "packet sum = %lld, average = %d\n", sum, (int)(sum / len));
#endif
	return sum / len;
}

static long long tvdiff_ms_or_zero(struct timeval end, struct timeval start)
{
	if (ast_tvzero(end) || ast_tvzero(start)) {
		return 0;
	} else {
		return ast_tvdiff_ms(end, start);
	}
}

static void write_end_of_recognition_call_event(struct gdf_request *req)
{
	char duration_buffer[32] = "";
	char utterance_duration_buffer[32] = "";
	char speech_rec_duration_buffer[32] = "";
	char dialogflow_response_time_buffer[32] = "";
	char intent_latency_time_buffer[32] = "";
	char endpointer_barge_in_time_buffer[32] = "";
	char dialogflow_barge_in_time_buffer[32] = "";
	struct timeval dialogflow_start_time = df_get_session_start_time(req->session);
	struct timeval last_transcription_time = df_get_session_last_transcription_time(req->session);
	struct timeval intent_detect_time = df_get_session_intent_detected_time(req->session);
	struct dialogflow_log_data log_data[] = {
		{ "duration_ms", duration_buffer },
		{ "utterance_duration_ms", utterance_duration_buffer },
		{ "speech_rec_duration_ms", speech_rec_duration_buffer },
		{ "dialogflow_response_time_ms", dialogflow_response_time_buffer },
		{ "intent_latency_time_ms", intent_latency_time_buffer },
		{ "endpointer_barge_in_ms", endpointer_barge_in_time_buffer },
		{ "dialogflow_barge_in_ms", dialogflow_barge_in_time_buffer },
		{ "pre_recording", req->pre_recording_filename },
		{ "post_recording", req->post_recording_filename }
	};

	sprintf(duration_buffer, "%lld", req->last_request_duration_ms);
	sprintf(utterance_duration_buffer, "%lld", req->last_audio_duration_ms);
	sprintf(speech_rec_duration_buffer, "%lld", tvdiff_ms_or_zero(last_transcription_time, dialogflow_start_time));
	sprintf(dialogflow_response_time_buffer, "%lld", tvdiff_ms_or_zero(intent_detect_time, last_transcription_time));
	sprintf(intent_latency_time_buffer, "%lld", tvdiff_ms_or_zero(intent_detect_time, req->endpointer_end_of_speech_time));
	sprintf(endpointer_barge_in_time_buffer, "%lld", tvdiff_ms_or_zero(req->endpointer_barge_in_time, req->request_start));
	sprintf(dialogflow_barge_in_time_buffer, "%lld", tvdiff_ms_or_zero(req->dialogflow_barge_in_time, req->request_start));

	gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "stop", ARRAY_LEN(log_data), log_data);
}

static int open_preendpointed_recording_file(struct gdf_request *req)
{
	struct ast_str *path = build_log_related_filename_to_thread_local_str(req->pvt, req, "pre", "ul");
	FILE *record_file;

	ao2_lock(req);
	req->utterance_preendpointer_recording_open_already_attempted = 1;
	ao2_unlock(req);

	record_file = fopen(ast_str_buffer(path), "w");
	if (record_file) {
		struct dialogflow_log_data log_data[] = {
			{ "filename", ast_str_buffer(path) }
		};
		gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "pre_recording_start", ARRAY_LEN(log_data), log_data);
		ast_log(LOG_DEBUG, "Opened %s for preendpointer recording for %d@%s\n", ast_str_buffer(path), req->current_utterance_number, req->pvt->session_id);
		ao2_lock(req);
		ast_string_field_set(req, pre_recording_filename, ast_str_buffer(path));
		req->utterance_preendpointer_recording_file_handle = record_file;
		ao2_unlock(req);
	} else {
		ast_log(LOG_WARNING, "Unable to open %s for preendpointer recording for %d@%s -- %d: %s\n", ast_str_buffer(path), req->current_utterance_number, req->pvt->session_id, errno, strerror(errno));
	}

	return (record_file == NULL ? -1 : 0);
}

static int open_postendpointed_recording_file(struct gdf_request *req)
{
	struct ast_str *path = build_log_related_filename_to_thread_local_str(req->pvt, req, "post", "ul");
	FILE *record_file;

	ao2_lock(req);
	req->utterance_postendpointer_recording_open_already_attempted = 1;
	ao2_unlock(req);

	record_file = fopen(ast_str_buffer(path), "w");
	if (record_file) {
		struct dialogflow_log_data log_data[] = {
			{ "filename", ast_str_buffer(path) }
		};
		gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "post_recording_start", ARRAY_LEN(log_data), log_data);
		ast_log(LOG_DEBUG, "Opened %s for postendpointer recording for %d@%s\n", ast_str_buffer(path), req->current_utterance_number, req->pvt->session_id);
		ao2_lock(req);
		ast_string_field_set(req, post_recording_filename, ast_str_buffer(path));
		req->utterance_postendpointer_recording_file_handle = record_file;
		ao2_unlock(req);
	} else {
		ast_log(LOG_WARNING, "Unable to open %s for postendpointer recording for %d@%s -- %d: %s\n", ast_str_buffer(path), req->current_utterance_number, req->pvt->session_id, errno, strerror(errno));
	}

	return (record_file == NULL ? -1 : 0);
}

static void coalesce_cached_audio_for_writing(struct gdf_request *req)
{
	ao2_lock(req);
	if (req->mulaw_endpointer_audio_cache) {
		size_t end_amount_at_beginning_of_buffer;
		
		if (req->mulaw_endpointer_audio_cache_start == 0) {
			end_amount_at_beginning_of_buffer = 0;
		} else if (req->mulaw_endpointer_audio_cache_start + req->mulaw_endpointer_audio_cache_len > req->mulaw_endpointer_audio_cache_size) {
			end_amount_at_beginning_of_buffer = (req->mulaw_endpointer_audio_cache_start + req->mulaw_endpointer_audio_cache_len) - req->mulaw_endpointer_audio_cache_size;
		} else {
			ast_log(LOG_DEBUG, "Audio cache buffer for %d@%s not a full buffer but starts in middle\n", req->current_utterance_number, req->pvt->session_id);
			end_amount_at_beginning_of_buffer = 0;
		}

		if (end_amount_at_beginning_of_buffer == 0) {
			if (req->mulaw_endpointer_audio_cache_start == 0) {
				/* nothing to do */
			} else {
				char *start_of_cached_audio = req->mulaw_endpointer_audio_cache + req->mulaw_endpointer_audio_cache_start;
				memmove(req->mulaw_endpointer_audio_cache, start_of_cached_audio, req->mulaw_endpointer_audio_cache_len);
				req->mulaw_endpointer_audio_cache_start = 0;
			}
		} else {
			char *cache = alloca(end_amount_at_beginning_of_buffer);
			char *start_of_cached_audio = req->mulaw_endpointer_audio_cache + req->mulaw_endpointer_audio_cache_start;
			size_t amount_of_audio_at_end_of_buffer = req->mulaw_endpointer_audio_cache_size - req->mulaw_endpointer_audio_cache_start;
			char *where_end_of_audio_will_go = req->mulaw_endpointer_audio_cache + amount_of_audio_at_end_of_buffer;

			memcpy(cache, req->mulaw_endpointer_audio_cache, end_amount_at_beginning_of_buffer);
			memmove(req->mulaw_endpointer_audio_cache, start_of_cached_audio, amount_of_audio_at_end_of_buffer);
			memcpy(where_end_of_audio_will_go, cache, end_amount_at_beginning_of_buffer);

			req->mulaw_endpointer_audio_cache_start = 0;
		}
	}
	ao2_unlock(req);
}

static void maybe_record_audio(struct gdf_request *req, const char *mulaw, size_t mulaw_len, enum VAD_STATE current_vad_state)
{
	struct gdf_config *config = gdf_get_config();
	int enable_preendpointer_recordings = 0;
	int enable_postendpointer_recordings = 0;
	int record_preendpointer_on_demand = 0;
	int currently_recording_preendpointed_audio = 0;
	int currently_recording_postendpointed_audio = 0;
	int already_attempted_open_for_preendpointed_audio = 0;
	int already_attempted_open_for_postendpointed_audio = 0;

	if (config) {
		enable_preendpointer_recordings = config->enable_preendpointer_recordings;
		enable_postendpointer_recordings = config->enable_postendpointer_recordings;		
		record_preendpointer_on_demand = config->record_preendpointer_on_demand;
		ao2_t_ref(config, -1, "done with config checking for recording");
	}

	enable_postendpointer_recordings |= req->record_utterance;
	if (record_preendpointer_on_demand) {
		enable_preendpointer_recordings |= req->record_utterance;
	}
	
	if (enable_postendpointer_recordings || enable_preendpointer_recordings) {
		int have_call_log_path;
		ao2_lock(req);
		have_call_log_path = !ast_strlen_zero(req->pvt->call_log_path);
		if (have_call_log_path) {
			currently_recording_preendpointed_audio = (req->utterance_preendpointer_recording_file_handle != NULL);
			already_attempted_open_for_preendpointed_audio = req->utterance_preendpointer_recording_open_already_attempted;
			currently_recording_postendpointed_audio = (req->utterance_postendpointer_recording_file_handle != NULL);
			already_attempted_open_for_postendpointed_audio = req->utterance_postendpointer_recording_open_already_attempted;
		}
		ao2_unlock(req);
	}

	if (enable_preendpointer_recordings) {
		if (!currently_recording_preendpointed_audio && !already_attempted_open_for_preendpointed_audio) {
			if (!open_preendpointed_recording_file(req)) {
				currently_recording_preendpointed_audio = 1;
			}
		}
		if (currently_recording_preendpointed_audio) {
			size_t written = fwrite(mulaw, sizeof(char), mulaw_len, req->utterance_preendpointer_recording_file_handle);
			if (written < mulaw_len) {
				ast_log(LOG_WARNING, "Only wrote %d of %d bytes for pre-endpointed recording for%d@%s\n",
					(int) written, (int) mulaw_len, req->current_utterance_number, req->pvt->session_id);
			}
		}
	}

	if (enable_postendpointer_recordings && current_vad_state != VAD_STATE_START) {
		int need_to_dump_cached_audio = 0;
		if (!currently_recording_postendpointed_audio && !already_attempted_open_for_postendpointed_audio) {
			if (!open_postendpointed_recording_file(req)) {
				currently_recording_postendpointed_audio = 1;
				need_to_dump_cached_audio = 1;
			}
		}
		if (need_to_dump_cached_audio) {
			size_t written;
			coalesce_cached_audio_for_writing(req);
			written = fwrite(req->mulaw_endpointer_audio_cache, sizeof(char), req->mulaw_endpointer_audio_cache_len, req->utterance_postendpointer_recording_file_handle);
			if (written < req->mulaw_endpointer_audio_cache_len) {
				ast_log(LOG_WARNING, "Only wrote %d of %d bytes for cached post-endpointed recording for %d@%s\n",
					(int) written, (int) req->mulaw_endpointer_audio_cache_len, req->current_utterance_number, req->pvt->session_id);
			}
		}
		if (currently_recording_postendpointed_audio) {
			size_t written = fwrite(mulaw, sizeof(char), mulaw_len, req->utterance_postendpointer_recording_file_handle);
			if (written < mulaw_len) {
				ast_log(LOG_WARNING, "Only wrote %d of %d bytes for post-endpointed recording for %d@%s\n",
					(int) written, (int) mulaw_len, req->current_utterance_number, req->pvt->session_id);
			}
		}
	}
}

static void maybe_cache_preendpointed_audio(struct gdf_request *req, const char *mulaw, size_t mulaw_len, enum VAD_STATE vad_state)
{
	if (vad_state == VAD_STATE_START) {
		ao2_lock(req);
		if (req->mulaw_endpointer_audio_cache) {
			size_t relative_write_location;
			char *write_location;

			if (req->mulaw_endpointer_audio_cache_len + mulaw_len > req->mulaw_endpointer_audio_cache_size) {
				size_t space_needed = req->mulaw_endpointer_audio_cache_len + mulaw_len - req->mulaw_endpointer_audio_cache_size;
				req->mulaw_endpointer_audio_cache_start += space_needed;
				req->mulaw_endpointer_audio_cache_len -= space_needed;
				if (req->mulaw_endpointer_audio_cache_start >= req->mulaw_endpointer_audio_cache_size) {
					req->mulaw_endpointer_audio_cache_start -= req->mulaw_endpointer_audio_cache_size;
				}
			}

			relative_write_location = req->mulaw_endpointer_audio_cache_start + req->mulaw_endpointer_audio_cache_len;
			if (relative_write_location >= req->mulaw_endpointer_audio_cache_size) {
				relative_write_location -= req->mulaw_endpointer_audio_cache_size;
			}
			
			write_location = req->mulaw_endpointer_audio_cache + relative_write_location;

			memcpy(write_location, mulaw, mulaw_len);
			req->mulaw_endpointer_audio_cache_len += mulaw_len;
		}
		ao2_unlock(req);
	}
}

static void close_preendpointed_audio_recording(struct gdf_request *req)
{
	if (req->utterance_preendpointer_recording_file_handle) {
		fclose(req->utterance_preendpointer_recording_file_handle);
		req->utterance_preendpointer_recording_file_handle = NULL;
		gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "pre_recording_stop");
	}
	req->utterance_preendpointer_recording_open_already_attempted = 0;
}

static void close_postendpointed_audio_recording(struct gdf_request *req)
{
	if (req->utterance_postendpointer_recording_file_handle) {
		fclose(req->utterance_postendpointer_recording_file_handle);
		req->utterance_postendpointer_recording_file_handle = NULL;
		gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "post_recording_stop");
	}
	req->utterance_postendpointer_recording_open_already_attempted = 0;
}

static int gdf_stop_recognition(struct gdf_request *req)
{
	close_preendpointed_audio_recording(req);
	close_postendpointed_audio_recording(req);
	df_stop_recognition(req->session);
	ao2_lock(req->pvt);
	if (req == req->pvt->current_request) {
		if (req->pvt->speech) {
			ast_speech_change_state(req->pvt->speech, AST_SPEECH_STATE_DONE); /* okay to call this locked */
		}
	}
	ao2_unlock(req->pvt);
	req->last_request_duration_ms = ast_tvdiff_ms(ast_tvnow(), req->request_start);
	write_end_of_recognition_call_event(req);
	return 0;
}

/* speech structure is locked */
static int gdf_write(struct ast_speech *speech, void *data, int len)
{
	struct gdf_pvt *pvt = speech->data;
	int res = 0;
	struct ast_frame f;
	struct ast_frame *iso;
	
	memset(&f, 0, sizeof(f));
	
	f.frametype = AST_FRAME_VOICE;
#ifdef ASTERISK_13_OR_LATER
	f.subclass.format = ast_format_slin;
#else
	f.subclass.codec = AST_FORMAT_SLINEAR;
#endif
	f.data.ptr = data;
	f.datalen = len;
	f.samples = len / 2;
	f.src = "gdf_write";
	
	iso = ast_frisolate(&f);
	if (iso) {
		ao2_lock(pvt);
		if (pvt->current_request) {
			ao2_lock(pvt->current_request);
			AST_LIST_INSERT_TAIL(&pvt->current_request->frame_queue, iso, frame_list);
			pvt->current_request->frame_queue_len++;
			ao2_unlock(pvt->current_request);
		} else {
			ast_frfree(iso);
		}
		ao2_unlock(pvt);
	} else {
		ast_log(LOG_WARNING, "Error isolating frame for write to %s\n",
			pvt->session_id);
	}
	
	return res;
}

static int gdf_dtmf(struct ast_speech *speech, const char *dtmf)
{
	return -1;
}

static int should_start_call_log(struct gdf_pvt *pvt)
{
	int should_start;
	ao2_lock(pvt);
	should_start = !pvt->call_log_open_already_attempted;
	ao2_unlock(pvt);
	if (should_start) {
		struct gdf_config *cfg;
		cfg = gdf_get_config();
		if (cfg) {
			should_start &= cfg->enable_call_logs;
			ao2_t_ref(cfg, -1, "done checking for starting call log");
		}
	}
	return should_start;
}

AST_THREADSTORAGE(call_log_path);
static void calculate_log_path(struct gdf_pvt *pvt)
{
	struct varshead var_head = { .first = NULL, .last = NULL };
	struct ast_var_t *var;
	struct gdf_config *cfg;

	ao2_lock(pvt);
	var = ast_var_assign("APPLICATION", pvt->call_logging_application_name);
	ao2_unlock(pvt);

	AST_LIST_INSERT_HEAD(&var_head, var, entries);

	cfg = gdf_get_config();
	if (cfg) {
		struct ast_str *path = ast_str_thread_get(&call_log_path, 256);

		ast_str_substitute_variables_varshead(&path, 0, &var_head, cfg->call_log_location);

		ao2_lock(pvt);
		ast_string_field_set(pvt, call_log_path, ast_str_buffer(path));
		ao2_unlock(pvt);

		ao2_t_ref(cfg, -1, "done with config in calculating call log path");
	}
	
	ast_var_delete(var);
}

static void calculate_log_file_basename(struct gdf_pvt *pvt)
{
	struct timeval t;
	struct ast_tm now;
	
	t = ast_tvnow();
	ast_localtime(&t, &now, NULL);
	ast_string_field_build(pvt, call_log_file_basename, "%02d%02d_%s", now.tm_min, now.tm_sec, pvt->session_id);
}

static void mkdir_log_path(struct gdf_pvt *pvt)
{
	ast_mkdir(pvt->call_log_path, 0755);
}

static struct ast_str *build_log_related_filename_to_thread_local_str(struct gdf_pvt *pvt, struct gdf_request *req, const char *type, const char *extension)
{
	struct ast_str *path;
	path = ast_str_thread_get(&call_log_path, 256);
	ao2_lock(pvt);
	ast_str_set(&path, 0, "%s", pvt->call_log_path);
	ast_str_append(&path, 0, "%s", pvt->call_log_file_basename);
	ast_str_append(&path, 0, "_%s", type);
	if (req) {
		ast_str_append(&path, 0, "_%d", req->current_utterance_number);
	}
	ast_str_append(&path, 0, ".%s" , extension);
	ao2_unlock(pvt);
	return path;
}

static void start_call_log(struct gdf_pvt *pvt)
{
	ao2_lock(pvt);
	if (pvt->call_log_open_already_attempted) {
		ao2_unlock(pvt);
		return;
	}
	pvt->call_log_open_already_attempted = 1;
	ao2_unlock(pvt);

	calculate_log_path(pvt);
	calculate_log_file_basename(pvt);

	if (!ast_strlen_zero(pvt->call_log_path)) {
		struct ast_str *path;
		FILE *log_file;

		mkdir_log_path(pvt);

		path = build_log_related_filename_to_thread_local_str(pvt, NULL, "log", "jsonl");

		log_file = fopen(ast_str_buffer(path), "w");
		if (log_file) {
			char hostname[HOST_NAME_MAX] = "";
			struct dialogflow_log_data log_data[] = {
				{ "application", pvt->call_logging_application_name },
				{ "hostname", hostname }
			};

			gethostname(hostname, sizeof(hostname) - 1);

			ast_log(LOG_DEBUG, "Opened %s for call log for %s\n", ast_str_buffer(path), pvt->session_id);
			ao2_lock(pvt);
			pvt->call_log_file_handle = log_file;
			ao2_unlock(pvt);

			gdf_log_call_event(pvt, NULL, CALL_LOG_TYPE_SESSION, "start", ARRAY_LEN(log_data), log_data);
		} else {
			ast_log(LOG_WARNING, "Unable to open %s for writing call log for %s -- %d: %s\n", ast_str_buffer(path), pvt->session_id, errno, strerror(errno));
		}
	} else {
		ast_log(LOG_WARNING, "Not starting call log, path is empty\n");
	}
}

static void log_endpointer_start_event(struct gdf_request *req)
{
	char threshold[11];
	char voice_duration[11];
	char silence_duration[11];
	char barge_duration[11];
	char end_of_speech_duration[11];
	struct dialogflow_log_data log_data[] = {
		{ VAD_PROP_VOICE_THRESHOLD, threshold },
		{ VAD_PROP_VOICE_DURATION, voice_duration },
		{ VAD_PROP_SILENCE_DURATION, silence_duration },
		{ VAD_PROP_BARGE_DURATION, barge_duration },
		{ VAD_PROP_END_OF_SPEECH_DURATION, end_of_speech_duration }
	};

	sprintf(threshold, "%d", req->voice_threshold);
	sprintf(voice_duration, "%d", req->voice_minimum_duration);
	sprintf(silence_duration, "%d", req->silence_minimum_duration);
	sprintf(barge_duration, "%d", req->barge_in_minimum_duration);
	sprintf(end_of_speech_duration, "%d", req->end_of_speech_minimum_silence);

	gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "start", ARRAY_LEN(log_data), log_data);
}

static int gdf_start(struct ast_speech *speech)
{
	struct gdf_pvt *pvt = speech->data;

	if (should_start_call_log(pvt)) {
		start_call_log(pvt);
	}

	ao2_lock(pvt);
	if (pvt->current_request) {
		ao2_t_ref(pvt->current_request, -1, "Cancel in-progress request for a new one");
		pvt->current_request = NULL;
	}
	pvt->current_request = create_new_request(pvt, pvt->utterance_counter++);
	ao2_unlock(pvt);
	if (pvt->current_request == NULL) {
		ast_speech_change_state(pvt->speech, AST_SPEECH_STATE_DONE);
		return -1;
	}

	return 0;
}

static void maybe_signal_speaking(struct gdf_request *req, enum dialogflow_session_state state)
{
	ao2_lock(req->pvt);
	if (req->pvt->current_request == req) {
		if (state == DF_STATE_STARTED && req->pvt->speech && !ast_test_flag(req->pvt->speech, AST_SPEECH_SPOKE)) {
			ast_log(LOG_DEBUG, "Setting heard speech on %d@%s\n", req->current_utterance_number, req->pvt->session_id);
			ast_set_flag(req->pvt->speech, AST_SPEECH_QUIET);
			ast_set_flag(req->pvt->speech, AST_SPEECH_SPOKE);
		}
	}
	ao2_unlock(req->pvt);
}

static void mark_request_done(struct gdf_request *req)
{
	ao2_lock(req);
	req->state = GDFE_STATE_DONE;
	ao2_unlock(req);
}

static int write_audio_frame(struct gdf_request *req, void *data, int len)
{
	enum dialogflow_session_state state;
	enum VAD_STATE vad_state;
#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	enum VAD_STATE orig_vad_state;
#endif
	int threshold;
	int cur_duration;
	int change_duration;
	int avg_level;
	int voice_duration;
	int silence_duration;
	int barge_duration;
	int end_of_speech_duration;
	int heard_speech;
	milliseconds_t incomplete_timeout;
	milliseconds_t no_speech_timeout;
	milliseconds_t maximum_speech_timeout;
	int datasamples;
	int datams;
	int mulaw_len;
	char *mulaw;
	int i;
	int start_recognition_on_start = 0;
	int recognition_start_failure_retries = 0;
	int recognition_start_failure_retry_max_time_ms = 0;
	const char *start_failure_retry_codes = "";
	struct gdf_config *cfg;
	int signal_end_of_speech = 0;

	datasamples = len / sizeof(short); /* 2 bytes per sample for slin */;
	datams = datasamples / 8; /* 8 samples per millisecond */;
	mulaw_len = datasamples * sizeof(char);
	mulaw = alloca(mulaw_len);

	ao2_lock(req);
#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	orig_vad_state = req->vad_state;
#endif
	vad_state = req->vad_state;
	threshold = req->voice_threshold;
	cur_duration = req->vad_state_duration;
	change_duration = req->vad_change_duration;
	voice_duration = req->voice_minimum_duration;
	silence_duration = req->silence_minimum_duration;
	barge_duration = req->barge_in_minimum_duration;
	end_of_speech_duration = req->end_of_speech_minimum_silence;
	heard_speech = req->heard_speech;
	incomplete_timeout = req->incomplete_timeout;
	no_speech_timeout = req->no_speech_timeout;
	maximum_speech_timeout = req->maximum_speech_timeout;
	ao2_unlock(req);

	cfg = gdf_get_config();
	if (cfg) {
		start_recognition_on_start = cfg->start_recognition_on_start;
		recognition_start_failure_retries = cfg->recognition_start_failure_retries;
		recognition_start_failure_retry_max_time_ms = cfg->recognition_start_failure_retry_max_time_ms;
		start_failure_retry_codes = ast_strdupa(cfg->start_failure_retry_codes);
		ao2_t_ref(cfg, -1, "done checking for starting rec on call start");
	}

	state = df_get_state(req->session);

	cur_duration += datams;

	avg_level = calculate_audio_level((short *)data, datasamples);
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
			cur_duration = change_duration;
			change_duration = 0;
			ao2_lock(req);
			req->speech_start = ast_tvnow();
			ao2_unlock(req);
			gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "start_of_speech");
		}
	} else if (vad_state == VAD_STATE_SPEAK) {
		if (change_duration >= silence_duration) {
			vad_state = VAD_STATE_SILENT;
			cur_duration = change_duration;
			change_duration = 0;
		} else if (cur_duration >= barge_duration) {
			if (!heard_speech) {
				heard_speech = 1;
				gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "barge_in");
				maybe_signal_speaking(req, state);
			}
			if (ast_tvzero(req->endpointer_barge_in_time)) {
				req->endpointer_barge_in_time = ast_tvnow();
			}
		}
	} else if (vad_state == VAD_STATE_SILENT) {
		if (change_duration >= voice_duration) {
			vad_state = VAD_STATE_SPEAK;
			cur_duration = change_duration;
			change_duration = 0;
		} else if (heard_speech && cur_duration >= end_of_speech_duration) {
			vad_state = VAD_STATE_END;
			gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "end_of_speech");
			ao2_lock(req);
			req->endpointer_end_of_speech_time = ast_tvnow();
			signal_end_of_speech = req->pvt->use_internal_endpointer_for_end_of_speech;
			ao2_unlock(req);
		}
	}
	
	ao2_lock(req);
	req->vad_state = vad_state;
	req->vad_state_duration = cur_duration;
	req->vad_change_duration = change_duration;
	req->heard_speech = heard_speech;
	ao2_unlock(req);

#ifdef RES_SPEECH_GDFE_DEBUG_VAD
	ast_log(LOG_DEBUG, "avg: %d thr: %d dur: %d chg: %d vce: %d sil: %d old: %d new: %d\n",
		avg_level, threshold, cur_duration, change_duration, voice_duration, silence_duration, 
		orig_vad_state, vad_state);
#endif

	if (state == DF_STATE_READY && start_recognition_on_start) {
		if (ast_tvzero(req->recognition_initial_attempt)) {
			req->recognition_initial_attempt = ast_tvnow();
		}
		if (df_start_recognition(req->session, req->language, 0, (const char **)req->pvt->hints, req->pvt->hint_count)) {
			int will_retry = 0;
			long long retry_duration = ast_tvdiff_ms(ast_tvnow(), req->recognition_initial_attempt);
			if (req->current_start_retry < recognition_start_failure_retries && retry_duration < recognition_start_failure_retry_max_time_ms) {
				int results;
				int result_number;
				ast_log(LOG_DEBUG, "Error pre-starting recognition on %d@%s -- might retry\n", req->current_utterance_number, req->pvt->session_id);
				df_stop_recognition(req->session);
				results = df_get_result_count(req->session);
				for (result_number = 0; result_number < results; result_number++) {
					struct dialogflow_result *df_result = df_get_result(req->session, result_number);
					if (!strcasecmp(df_result->slot, "error_code")) {
						size_t code_len = strlen(df_result->value);
						char *comma_code = alloca(code_len + 3);

						sprintf(comma_code, ",%s,", df_result->value);
						if (strstr(start_failure_retry_codes, comma_code)) {
							will_retry = 1;
						}
						break;
					}
				}
			}
			if (will_retry) {
				ast_log(LOG_DEBUG, "Error pre-starting recognition on %d@%s -- will retry\n", req->current_utterance_number, req->pvt->session_id);
				req->current_start_retry++;
				vad_state = VAD_STATE_START;
			} else {
				ast_log(LOG_WARNING, "Error pre-starting recognition on %d@%s\n", req->current_utterance_number, req->pvt->session_id);
				mark_request_done(req);
			}
		}
		ao2_lock(req);
		req->last_audio_duration_ms = 0;
		ao2_unlock(req);
	}

	for (i = 0; i < datasamples; i++) {
		mulaw[i] = AST_LIN2MU(((short *)data)[i]);
	}
	
	maybe_record_audio(req, mulaw, mulaw_len, vad_state);
	maybe_cache_preendpointed_audio(req, mulaw, mulaw_len, vad_state);

	state = df_get_state(req->session);
	if (vad_state != VAD_STATE_START) {
		if (state == DF_STATE_READY) {
			if (!start_recognition_on_start) {
				if (ast_tvzero(req->recognition_initial_attempt)) {
					req->recognition_initial_attempt = ast_tvnow();
				}
				if (df_start_recognition(req->session, req->language, 0, (const char **)req->pvt->hints, req->pvt->hint_count)) {
					int will_retry = 0;
					long long retry_duration = ast_tvdiff_ms(ast_tvnow(), req->recognition_initial_attempt);
					if (req->current_start_retry < recognition_start_failure_retries && retry_duration < recognition_start_failure_retry_max_time_ms) {
						int results;
						int result_number;
						ast_log(LOG_DEBUG, "Error starting recognition on %d@%s -- might retry\n", req->current_utterance_number, req->pvt->session_id);
						df_stop_recognition(req->session);
						results = df_get_result_count(req->session);
						for (result_number = 0; result_number < results; result_number++) {
							struct dialogflow_result *df_result = df_get_result(req->session, result_number);
							if (!strcasecmp(df_result->slot, "error_code")) {
								size_t code_len = strlen(df_result->value);
								char *comma_code = alloca(code_len + 3);

								sprintf(comma_code, ",%s,", df_result->value);
								if (strstr(start_failure_retry_codes, comma_code)) {
									will_retry = 1;
								}
								break;
							}
						}
					}
					if (will_retry) {
						size_t new_audio_cache_size;
						char *new_audio_cache;
						ast_log(LOG_DEBUG, "Error starting recognition on %d@%s -- will retry\n", req->current_utterance_number, req->pvt->session_id);
						req->current_start_retry++;
						coalesce_cached_audio_for_writing(req);
						new_audio_cache_size = req->mulaw_endpointer_audio_cache_size + 160; /* 20 ms more */
						new_audio_cache = ast_realloc(req->mulaw_endpointer_audio_cache, new_audio_cache_size);
						if (new_audio_cache) {
							req->mulaw_endpointer_audio_cache_size = new_audio_cache_size;
							req->mulaw_endpointer_audio_cache = new_audio_cache;
						} else {
							ast_log(LOG_WARNING, "Unable to resize audio cache for %d@%s -- will lose audio\n", req->current_utterance_number, req->pvt->session_id);
						}
					} else {
						ast_log(LOG_WARNING, "Error starting recognition on %d@%s\n", req->current_utterance_number, req->pvt->session_id);
						mark_request_done(req);
					}
				}
				ao2_lock(req);
				req->last_audio_duration_ms = 0;
				ao2_unlock(req);
			}

			state = df_get_state(req->session);

			if (state == DF_STATE_STARTED) {
				size_t flush_start = 0;

				coalesce_cached_audio_for_writing(req);

				while (flush_start < req->mulaw_endpointer_audio_cache_len && state != DF_STATE_FINISHED && state != DF_STATE_ERROR) {
					if (flush_start + mulaw_len <= req->mulaw_endpointer_audio_cache_len) {
						state = df_write_audio(req->session, req->mulaw_endpointer_audio_cache + flush_start, mulaw_len);
						flush_start += mulaw_len;
					} else {
						size_t partial_write_size = req->mulaw_endpointer_audio_cache_len - flush_start;
						state = df_write_audio(req->session, req->mulaw_endpointer_audio_cache + flush_start, partial_write_size);
						flush_start += partial_write_size;
					}
				}

				ao2_lock(req);
				req->last_audio_duration_ms += flush_start / 8;
				ao2_unlock(req);
			}
		}

		if (state == DF_STATE_STARTED) {
			int response_count;
			state = df_write_audio(req->session, mulaw, mulaw_len);

			response_count = df_get_response_count(req->session);

			if (!heard_speech && response_count > 0) {
				heard_speech = 1;
				gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_ENDPOINTER, "auto_barge_in");
				maybe_signal_speaking(req, state);
			}
			if (ast_tvzero(req->dialogflow_barge_in_time) && response_count > 0) {
				req->dialogflow_barge_in_time = ast_tvnow();
			}

			ao2_lock(req);
			req->last_audio_duration_ms += mulaw_len / 8;
			req->heard_speech = heard_speech;
			ao2_unlock(req);

			if (incomplete_timeout > 0 && response_count > 0) {
				struct timeval now = ast_tvnow();
				struct timeval last_transcription_time = df_get_session_last_transcription_time(req->session);
				
				if (ast_tvdiff_ms(now, last_transcription_time) > incomplete_timeout) {
					gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "cancelled_incomplete");
					mark_request_done(req);
				}
			}
			if (no_speech_timeout > 0 && heard_speech && response_count == 0) {
				/* we heard speech but have gotten no speech responses */
				struct timeval now = ast_tvnow();
				struct timeval barge_in_time = req->endpointer_barge_in_time;

				if (ast_tvdiff_ms(now, barge_in_time) > no_speech_timeout) {
					gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "cancelled_no_speech");
					mark_request_done(req);
				}
			}
			if (maximum_speech_timeout > 0 && !ast_tvzero(req->speech_start)) {
				struct timeval now = ast_tvnow();
				struct timeval speech_start = req->speech_start;

				if (ast_tvdiff_ms(now, speech_start) > maximum_speech_timeout) {
					gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "cancelled_max_speech");
					mark_request_done(req);
				}
			}
		}
	}
 	if (signal_end_of_speech || state == DF_STATE_FINISHED || state == DF_STATE_ERROR) {
		mark_request_done(req);
	}

	return 0;
}

static int start_dialogflow_recognition(struct gdf_request *req)
{
	char *event = NULL;
	char *language = NULL;
	char *project_id = NULL;
	char *endpoint = NULL;
	char *service_key = NULL;
	char *model = NULL;
	int request_sentiment_analysis;
	int use_internal_endpointer_for_end_of_speech;
	enum SENTIMENT_ANALYSIS_STATE sentiment_analysis_state;

	ao2_lock(req->pvt);
	if (req->pvt->current_request != req) {
		ao2_unlock(req->pvt);
		return -1;
	}
	ao2_unlock(req->pvt);

	event = ast_strdupa(req->event);
	language = ast_strdupa(req->language);
	project_id = ast_strdupa(req->project_id);
	endpoint = ast_strdupa(req->endpoint);
	service_key = ast_strdupa(req->service_key);
	model = ast_strdupa(req->model);
	request_sentiment_analysis = req->pvt->request_sentiment_analysis;
	sentiment_analysis_state = req->pvt->effective_sentiment_analysis_state;
	use_internal_endpointer_for_end_of_speech = req->pvt->use_internal_endpointer_for_end_of_speech;

	req->vad_state = VAD_STATE_START;
	req->vad_state_duration = 0;
	req->vad_change_duration = 0;
	req->request_start = ast_tvnow();
	req->state = GDFE_STATE_PROCESSING;

	df_set_project_id(req->session, project_id);
	df_set_endpoint(req->session, endpoint);
	df_set_auth_key(req->session, service_key);

	if (request_sentiment_analysis) {
		if (sentiment_analysis_state == SENTIMENT_ANALYSIS_NEVER) {
			ast_log(LOG_DEBUG, "Refusing to do sentiment analysis on %d@%s due to configuration prohibition.\n", req->current_utterance_number, req->pvt->session_id);
			request_sentiment_analysis = 0;
		}
	} else {
		if (sentiment_analysis_state == SENTIMENT_ANALYSIS_ALWAYS) {
			ast_log(LOG_DEBUG, "Forcing sentiment analysis on %d@%s due to configuration.\n", req->current_utterance_number, req->pvt->session_id);
			request_sentiment_analysis = 1;
		}
	}
	ast_log(LOG_DEBUG, "%sequesting sentiment analysis on %d@%s\n", request_sentiment_analysis ? "R" : "Not r", req->current_utterance_number, req->pvt->session_id);
	df_set_request_sentiment_analysis(req->session, request_sentiment_analysis);
	df_set_use_external_endpointer(req->session, use_internal_endpointer_for_end_of_speech);
	df_set_model(req->session, model);

	{
		char utterance_number[11];
		struct dialogflow_log_data log_data[] = {
			{ "event", event },
			{ "language", language },
			{ "project_id", project_id },
			{ "logical_agent_name", req->pvt->logical_agent_name },
			{ "utterance", utterance_number },
			{ "context", req->pvt->call_logging_context },
			{ "application", req->pvt->call_logging_application_name }
		};
		sprintf(utterance_number, "%d", req->current_utterance_number);
		gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "start", ARRAY_LEN(log_data), log_data);
	}
	log_endpointer_start_event(req);
	
	if (!ast_strlen_zero(event)) {
		if (df_recognize_event(req->session, event, language, 0)) {
			ast_log(LOG_WARNING, "Error recognizing event on %d@%s\n", req->current_utterance_number, req->pvt->session_id);
			ao2_lock(req->pvt);
			if (req->pvt->current_request == req && req->pvt->speech) {
				ast_speech_change_state(req->pvt->speech, AST_SPEECH_STATE_DONE);
			}
			req->state = GDFE_STATE_HAVE_RESULTS;
			ao2_unlock(req->pvt);
		} else {
			ao2_lock(req);
			req->state = GDFE_STATE_DONE;
			ao2_unlock(req);
		}
	} else {
		df_connect(req->session);
	}

	return 0;
}

static void *gdf_exec(void *arg)
{
	struct gdf_request *req = arg;

	ast_log(LOG_DEBUG, "Starting background thread for GDF %d@%s\n", req->current_utterance_number, req->pvt->session_id);

	ao2_lock(req);
	while (req->state != GDFE_STATE_DONE)
	{
		struct timespec ts;
		int time_sleep_ms = 20;
		int cancelled;

		ao2_unlock(req);
		
		ts.tv_sec = time_sleep_ms / 1000;
		ts.tv_nsec = (time_sleep_ms % 1000) * 1000000;
		
		nanosleep(&ts, NULL);

		ao2_lock(req);
		if (req->state == GDFE_STATE_START) {
			ao2_unlock(req);
			start_dialogflow_recognition(req);
			ao2_lock(req);
		}
		ao2_unlock(req);
		ao2_lock(req->pvt);
		cancelled = req->pvt->current_request != req || (req->pvt->speech && req->pvt->speech->state == AST_SPEECH_STATE_NOT_READY);
		ao2_unlock(req->pvt);
		ao2_lock(req);
		if (req->state == GDFE_STATE_PROCESSING && cancelled) {
				ao2_unlock(req);
				gdf_log_call_event_only(req->pvt, req, CALL_LOG_TYPE_RECOGNITION, "cancelled");
				ao2_lock(req);
				req->state = GDFE_STATE_DONE;
		}
		while (req->state == GDFE_STATE_PROCESSING && req->frame_queue_len > 0) {
			struct ast_frame *f = AST_LIST_REMOVE_HEAD(&req->frame_queue, frame_list);
			req->frame_queue_len--;
			if (f) {
				ao2_unlock(req);
				write_audio_frame(req, f->data.ptr, f->datalen);
				ast_frfree(f);
				ao2_lock(req);
			}
		}
	}
	ao2_unlock(req);

	gdf_stop_recognition(req);

	ast_log(LOG_DEBUG, "Exiting background thread for GDF %d@%s\n", req->current_utterance_number, req->pvt->session_id);

	ao2_t_ref(req, -1, "Done with exec loop");

	return NULL;
}

static int gdf_change(struct ast_speech *speech, const char *name, const char *value)
{
	struct gdf_pvt *pvt = speech->data;

	if (!strcasecmp(name, GDF_PROP_SESSION_ID_NAME) || !strcasecmp(name, GDF_PROP_ALTERNATE_SESSION_NAME)) {
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Session ID must have a value, refusing to set to nothing (remains %s)\n", pvt->session_id);
			return -1;
		}
		ao2_lock(pvt);
		ast_string_field_set(pvt, session_id, value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, GDF_PROP_PROJECT_ID_NAME)) {
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Project ID must have a value, refusing to set to nothing (remains %s)\n", pvt->session_id);
			return -1;
		}
		ao2_lock(pvt);
		ast_string_field_set(pvt, project_id, value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, GDF_PROP_LANGUAGE_NAME)) {
		ao2_lock(pvt);
		ast_string_field_set(pvt, language, value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, GDF_PROP_LOG_CONTEXT) || !strcasecmp(name, GDF_PROP_ALTERNATE_LOG_CONTEXT)) {
		ao2_lock(pvt);
		ast_string_field_set(pvt, call_logging_context, value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, GDF_PROP_APPLICATION_CONTEXT)) {
		ao2_lock(pvt);
		ast_string_field_set(pvt, call_logging_application_name, value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_THRESHOLD)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_VOICE_THRESHOLD " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ao2_lock(pvt);
			pvt->voice_threshold = i;
			ao2_unlock(pvt);
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
			ao2_lock(pvt);
			if ((i % 20) != 0) {
				i = ((i / 20) + 1) * 20;
			}
			pvt->voice_minimum_duration = i;
			ao2_unlock(pvt);
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
			ao2_lock(pvt);
			pvt->silence_minimum_duration = i;
			ao2_unlock(pvt);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_SILENCE_DURATION " -- '%s'\n", value);
			return -1;
		}
	} else if (!strcasecmp(name, VAD_PROP_BARGE_DURATION)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_BARGE_DURATION " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ao2_lock(pvt);
			pvt->barge_in_minimum_duration = i;
			ao2_unlock(pvt);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_BARGE_DURATION " -- '%s'\n", value);
			return -1;
		}
	} else if (!strcasecmp(name, VAD_PROP_END_OF_SPEECH_DURATION)) {
		int i;
		if (ast_strlen_zero(value)) {
			ast_log(LOG_WARNING, "Cannot set " VAD_PROP_END_OF_SPEECH_DURATION " to an empty value\n");
			return -1;
		} else if (sscanf(value, "%d", &i) == 1) {
			ao2_lock(pvt);
			pvt->end_of_speech_minimum_silence = i;
			ao2_unlock(pvt);
		} else {
			ast_log(LOG_WARNING, "Invalid value for " VAD_PROP_END_OF_SPEECH_DURATION " -- '%s'\n", value);
			return -1;
		}
	} else if (!strcasecmp(name, GDF_PROP_REQUEST_SENTIMENT_ANALYSIS)) {
		ao2_lock(pvt);
		pvt->request_sentiment_analysis = ast_true(value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, "logPromptStart")) {
		struct dialogflow_log_data log_data[] = {
			{ "context", pvt->call_logging_context },
			{ "prompt", S_OR(value, "") }
		};
		gdf_log_call_event(pvt, pvt->current_request, CALL_LOG_TYPE_RECOGNITION, "prompt_start", ARRAY_LEN(log_data), log_data);
	} else if (!strcasecmp(name, "logPromptStop")) {
		struct dialogflow_log_data log_data[] = {
			{ "reason", S_OR(value, "none") }
		};
		gdf_log_call_event(pvt, pvt->current_request, CALL_LOG_TYPE_RECOGNITION, "prompt_stop", ARRAY_LEN(log_data), log_data);
	} else if (!strcasecmp(name, "logDtmf")) {
		struct dialogflow_log_data log_data[] = {
			{ "digits", S_OR(value, "") }
		};
		gdf_log_call_event(pvt, pvt->current_request, CALL_LOG_TYPE_RECOGNITION, "digits", ARRAY_LEN(log_data), log_data);
	} else if (!strcasecmp(name, "record") || !strcasecmp(name, "recordUtterance")) {
		ao2_lock(pvt);
		pvt->record_next_utterance = ast_true(value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, "incompleteTimeout")) {
		ao2_lock(pvt);
		pvt->incomplete_timeout = atoi(value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, "noSpeechTimeout")) {
		ao2_lock(pvt);
		pvt->no_speech_timeout = atoi(value);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, "maximumSpeechTimeout")) {
		ao2_lock(pvt);
		pvt->maximum_speech_timeout = atoi(value);
		ao2_unlock(pvt);
	} else {
		ast_log(LOG_DEBUG, "Unknown property '%s'\n", name);
		return -1;
	}

	return 0;
}

#ifdef AST_SPEECH_HAVE_GET_SETTING
static int gdf_get_setting(struct ast_speech *speech, const char *name, char *buf, size_t len)
{
	struct gdf_pvt *pvt = speech->data;

	if (!strcasecmp(name, GDF_PROP_UTTERANCE_DURATION_MS)) {
		long long last_audio_duration_ms = 0;
		ao2_lock(pvt);
		if (pvt->current_request) {
			last_audio_duration_ms = pvt->current_request->last_audio_duration_ms;
		}
		ao2_unlock(pvt);
		ast_build_string(&buf, &len, "%lld", last_audio_duration_ms);
	} else if (!strcasecmp(name, GDF_PROP_SESSION_ID_NAME)) {
		ast_copy_string(buf, pvt->session_id, len);
	} else if (!strcasecmp(name, GDF_PROP_PROJECT_ID_NAME)) {
		ast_copy_string(buf, pvt->session_id, len);
	} else if (!strcasecmp(name, GDF_PROP_LANGUAGE_NAME)) {
		ao2_lock(pvt);
		ast_copy_string(buf, pvt->language, len);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_THRESHOLD)) {
		ao2_lock(pvt);
		ast_build_string(&buf, &len, "%d", pvt->voice_threshold);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_VOICE_DURATION)) {
		ao2_lock(pvt);
		ast_build_string(&buf, &len, "%d", pvt->voice_minimum_duration);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_SILENCE_DURATION)) {
		ao2_lock(pvt);
		ast_build_string(&buf, &len, "%d", pvt->silence_minimum_duration);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_BARGE_DURATION)) {
		ao2_lock(pvt);
		ast_build_string(&buf, &len, "%d", pvt->barge_in_minimum_duration);
		ao2_unlock(pvt);
	} else if (!strcasecmp(name, VAD_PROP_END_OF_SPEECH_DURATION)) {
		ao2_lock(pvt);
		ast_build_string(&buf, &len, "%d", pvt->end_of_speech_minimum_silence);
		ao2_unlock(pvt);
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

static void add_speech_result(struct ast_speech_result **start, struct ast_speech_result **end, 
	const char *grammar, int score, const char *text)
{
	struct ast_speech_result *new = ast_calloc(1, sizeof(*new));
	if (new) {
		new->text = ast_strdup(text);
		new->score = score;
		new->grammar = ast_strdup(grammar);
	}

	if (*end) {
		AST_LIST_NEXT(*end, list) = new;
		*end = new;
	} else {
		*start = *end = new;
	}
}

static struct ast_speech_result *gdf_get_results(struct ast_speech *speech)
{
	/* speech is not locked */
	struct gdf_pvt *pvt = speech->data;
	struct gdf_request *req = pvt->current_request;
	int results;
	int i;
	struct ast_speech_result *start = NULL;
	struct ast_speech_result *end = NULL;
	static int last_resort = 0;

	struct dialogflow_result *fulfillment_text = NULL;
	struct dialogflow_result *output_audio = NULL;

	const char *audioFile = NULL;

	struct gdf_config *cfg;

	if (!req || !req->session) {
		return NULL;
	}

	cfg = gdf_get_config();
	results = df_get_result_count(req->session);

	for (i = 0; i < results; i++) {
		struct dialogflow_result *df_result = df_get_result(req->session, i); /* this is a borrowed reference */
		if (df_result) {
			if (!strcasecmp(df_result->slot, "output_audio")) {
				/* this is fine for now, but we really need a flag on the structure that says it's binary vs. text */
				output_audio = df_result;
			} else {
				add_speech_result(&start, &end, df_result->slot, df_result->score, df_result->value);

				if (!strcasecmp(df_result->slot, "fulfillment_text")) {
					fulfillment_text = df_result;
				}
			}
		}
	}

	ao2_lock(pvt);
	if (pvt->current_request) {
		char buffer[32];
		char *b = buffer;
		size_t l = sizeof(buffer);
		*b = '\0';
		ast_build_string(&b, &l, "%lld", pvt->current_request->last_audio_duration_ms);
		add_speech_result(&start, &end, "waveformDuration", 0, buffer);
	}
	ao2_unlock(pvt);

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
			ast_log(LOG_WARNING, "Unable to allocate speech result slot for fulfillment audio\n");
		}
	} else if (cfg->synthesize_fulfillment_text && fulfillment_text && !ast_strlen_zero(fulfillment_text->value)) {
		char tmpFilename[128];
		int fd;
		struct gdf_config *cfg;
		char *key;
		char *language;

		cfg = gdf_get_config();
		key = ast_strdupa(cfg->service_key);
		ao2_t_ref(cfg, -1, "done with creating session");

		ao2_lock(pvt);
		language = ast_strdupa(pvt->language);
		ao2_unlock(pvt);

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

	ao2_t_ref(cfg, -1, "done with config");

	if (!ast_strlen_zero(pvt->lastAudioResponse)) {
		unlink(pvt->lastAudioResponse);
		ast_string_field_set(pvt, lastAudioResponse, "");
	}
	if (!ast_strlen_zero(audioFile)) {
		ast_string_field_set(pvt, lastAudioResponse, audioFile);
	}

	return start;
}

static void gdf_config_destroy(void *o)
{
	struct gdf_config *conf = o;

	ast_string_field_free_memory(conf);

	if (conf->logical_agents) {
		ao2_ref(conf->logical_agents, -1);
	}
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

static void logical_agent_destructor(void *obj)
{
	struct gdf_logical_agent *agent = (struct gdf_logical_agent *) obj;
	if (agent->hints) {
		ao2_t_ref(agent->hints, -1, "destroying agent");
	}
	ast_string_field_free_memory(agent);
}

static void hint_destructor(void *obj)
{
	/* noop */
}

static void parse_hints(struct ao2_container *hints, const char *val)
{
	if (!ast_strlen_zero(val)) {
		char *val_copy = ast_strdupa(val);
		char *saved = NULL;
		char *hint;

		for (hint = strtok_r(val_copy, ",", &saved); hint; hint = strtok_r(NULL, ",", &saved)) {
			char *ao2_hint;
			hint = ast_strip(hint);
			if (!ast_strlen_zero(hint)) {
				size_t len = strlen(hint);
				ao2_hint = ao2_alloc(len + 1, hint_destructor);
				if (ao2_hint) {
					ast_copy_string(ao2_hint, hint, len + 1);
					ao2_link(hints, ao2_hint);
					ao2_t_ref(ao2_hint, -1, "linked hint on general load");
				}
			}
		}
	}
}

static struct gdf_logical_agent *logical_agent_alloc(const char *name, const char *project_id, 
	const char *service_key, const char *endpoint, enum SENTIMENT_ANALYSIS_STATE sentiment_analysis_state,
	const char *hints, int use_internal_endpointer_for_end_of_speech, const char *model)
{
	size_t name_len = strlen(name);
	size_t project_id_len = strlen(project_id);
	size_t service_key_len = strlen(service_key);
	size_t endpoint_len = strlen(endpoint);
	size_t model_len = strlen(model);
	size_t space_needed = name_len + 1 +
							project_id_len + 1 +
							service_key_len + 1 +
							endpoint_len + 1 + 
							model_len + 1;
	struct gdf_logical_agent *agent;
	
	agent = ao2_alloc(sizeof(struct gdf_logical_agent), logical_agent_destructor);
	if (!agent) {
		ast_log(LOG_WARNING, "Failed to allocate logical agent for %s\n", name);
		return NULL;
	}

	if (ast_string_field_init(agent, space_needed)) {
		ast_log(LOG_WARNING, "Failed to allocate string fields for logical agent %s\n", name);
		ao2_t_ref(agent, -1, "Failed to allocate string fields");
		return NULL;
	}

	ast_string_field_set(agent, name, name);
	ast_string_field_set(agent, project_id, project_id);
	ast_string_field_set(agent, service_key, service_key);
	ast_string_field_set(agent, endpoint, endpoint);
	agent->enable_sentiment_analysis = sentiment_analysis_state;
	agent->use_internal_endpointer_for_end_of_speech = use_internal_endpointer_for_end_of_speech;

	agent->hints = ao2_container_alloc(1, NULL, NULL);
	if (agent->hints && !ast_strlen_zero(hints)) {
		parse_hints(agent->hints, hints);
	}
	
	return agent;
}

static int logical_agent_hash_callback(const void *obj, const int flags)
{
	const struct gdf_logical_agent *agent = obj;
	return ast_str_case_hash(agent->name);
}

static int logical_agent_compare_callback(void *obj, void *other, int flags)
{
	const struct gdf_logical_agent *agentA = obj;
	const struct gdf_logical_agent *agentB = other;
	return (!strcasecmp(agentA->name, agentB->name) ? CMP_MATCH | CMP_STOP : 0);
}

static struct gdf_logical_agent *get_logical_agent_by_name(struct gdf_config *config, const char *name)
{
	struct gdf_logical_agent tmpAgent = { .name = name };
	return ao2_find(config->logical_agents, &tmpAgent, OBJ_POINTER);
}

static struct ast_str *load_service_key(const char *val)
{
	struct ast_str *buffer = ast_str_create(3 * 1024); /* big enough for the typical key size */
	if (!buffer) {
		ast_log(LOG_WARNING, "Memory allocation failure allocating ast_str for loading service key\n");
		return NULL;
	}

	if (strchr(val, '{')) {
		ast_str_set(&buffer, 0, "%s", val);
	} else {
		FILE *f;
		ast_log(LOG_DEBUG, "Loading service key data from %s\n", val);
		f = fopen(val, "r");
		if (f) {
			char readbuffer[512];
			size_t read = fread(readbuffer, sizeof(char), sizeof(readbuffer), f);
			while (read > 0) {
				ast_str_append_substr(&buffer, 0, readbuffer, read);
				read = fread(readbuffer, sizeof(char), sizeof(readbuffer), f);
			}
			if (ferror(f)) {
				ast_log(LOG_WARNING, "Error reading %s -- %d\n", val, errno);
			}
			fclose(f);
		} else {
			ast_log(LOG_ERROR, "Unable to open service key file %s -- %d\n", val, errno);
		}
	}

	return buffer;
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
		const char *category;

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

		conf->logical_agents = ao2_container_alloc(32, logical_agent_hash_callback, logical_agent_compare_callback);
		if (!conf->logical_agents) {
			ast_log(LOG_WARNING, "Failed to allocate logical agent container for speech gdf\n");
			ao2_ref(conf, -1);
			ast_config_destroy(cfg);
		}

		conf->hints = ao2_container_alloc(1, NULL, NULL);
		if (!conf->hints) {
			ast_log(LOG_WARNING, "Failed to allocate hint container for speech gdf\n");
		}

		val = ast_variable_retrieve(cfg, "general", "service_key");
		if (ast_strlen_zero(val)) {
			ast_log(LOG_VERBOSE, "Service key not provided -- will use default credentials.\n");
		} else {
			struct ast_str *buffer = load_service_key(val);
			ast_string_field_set(conf, service_key, ast_str_buffer(buffer));
			ast_free(buffer);
		}

		val = ast_variable_retrieve(cfg, "general", "endpoint");
		if (!ast_strlen_zero(val)) {
			ast_string_field_set(conf, endpoint, val);
		}

		conf->vad_voice_threshold = 1024;
		val = ast_variable_retrieve(cfg, "general", "vad_voice_threshold");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				conf->vad_voice_threshold = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_voice_threshold\n");
			}
		}

		conf->vad_voice_minimum_duration = 100; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_voice_minimum_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				if ((i % 20) != 0) {
					i = ((i / 20) + 1) * 20;
				}
				conf->vad_voice_minimum_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_voice_minimum_duration\n");
			}
		}

		conf->vad_silence_minimum_duration = 100; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_silence_minimum_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				if ((i % 20) != 0) {
					i = ((i / 20) + 1) * 20;
				}
				conf->vad_silence_minimum_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_silence_minimum_duration\n");
			}
		}

		conf->vad_barge_minimum_duration = 300; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_barge_minimum_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				if ((i % 20) != 0) {
					i = ((i / 20) + 1) * 20;
				}
				conf->vad_barge_minimum_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_barge_minimum_duration\n");
			}
		}

		conf->vad_end_of_speech_silence_duration = 500; /* ms */
		val = ast_variable_retrieve(cfg, "general", "vad_end_of_speech_silence_duration");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				if ((i % 20) != 0) {
					i = ((i / 20) + 1) * 20;
				}
				conf->vad_end_of_speech_silence_duration = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for vad_end_of_speech_silence_duration\n");
			}
		}

		conf->endpointer_cache_audio_pretrigger_ms = 100;
		val = ast_variable_retrieve(cfg, "general", "endpointer_cache_audio_pretrigger_ms");
		if (!ast_strlen_zero(val)) {
			int i;
			if (sscanf(val, "%d", &i) == 1) {
				if (i % 20 != 0) {
					int new_i = ((i / 20) + 1) * 20;
					ast_log(LOG_WARNING, "Rounding endpointer_cache_audio_pretrigger_ms from %d to %d to match packet size\n",
						i, new_i);
					i = new_i;
				}
				conf->endpointer_cache_audio_pretrigger_ms = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value for endpointer_cache_audio_pretrigger_ms\n");
			}
		}

		ast_string_field_set(conf, call_log_location, "/var/log/dialogflow/${APPLICATION}/${STRFTIME(,,%Y/%m/%d/%H)}/");
		val = ast_variable_retrieve(cfg, "general", "call_log_location");
		if (!ast_strlen_zero(val)) {
			ast_string_field_set(conf, call_log_location, val);
		}

		conf->enable_call_logs = 1;
		val = ast_variable_retrieve(cfg, "general", "enable_call_logs");
		if (!ast_strlen_zero(val)) {
			conf->enable_call_logs = ast_true(val);
		}

		conf->enable_preendpointer_recordings = 0;
		val = ast_variable_retrieve(cfg, "general", "enable_preendpointer_recordings");
		if (!ast_strlen_zero(val)) {
			conf->enable_preendpointer_recordings = ast_true(val);
		}

		conf->enable_postendpointer_recordings = 0;
		val = ast_variable_retrieve(cfg, "general", "enable_postendpointer_recordings");
		if (!ast_strlen_zero(val)) {
			conf->enable_postendpointer_recordings = ast_true(val);
		}

		conf->record_preendpointer_on_demand = 0;
		val = ast_variable_retrieve(cfg, "general", "record_preendpointer_on_demand");
		if (!ast_strlen_zero(val)) {
			conf->record_preendpointer_on_demand = ast_true(val);
		}

		conf->enable_sentiment_analysis = SENTIMENT_ANALYSIS_DEFAULT;
		val = ast_variable_retrieve(cfg, "general", "enable_sentiment_analysis");
		if (!ast_strlen_zero(val)) {
			if (ast_true(val) || !strcasecmp(val, "always")) {
				conf->enable_sentiment_analysis = SENTIMENT_ANALYSIS_ALWAYS;
			} else if (!strcasecmp(val, "default")) {
				conf->enable_sentiment_analysis = SENTIMENT_ANALYSIS_DEFAULT;
			} else {
				conf->enable_sentiment_analysis = SENTIMENT_ANALYSIS_NEVER;
			}
		}

		conf->stop_writes_on_final_transcription = 1;
		val = ast_variable_retrieve(cfg, "general", "stop_writes_on_final_transcription");
		if (!ast_strlen_zero(val)) {
			conf->stop_writes_on_final_transcription = ast_true(val);
		}

		conf->start_recognition_on_start = 0;
		val = ast_variable_retrieve(cfg, "general", "start_recognition_on_start");
		if (!ast_strlen_zero(val)) {
			conf->start_recognition_on_start = ast_true(val);
		}

		conf->synthesize_fulfillment_text = 0;
		val = ast_variable_retrieve(cfg, "general", "synthesize_fulfillment_text");
		if (!ast_strlen_zero(val)) {
			conf->synthesize_fulfillment_text = ast_true(val);
		}

		conf->use_internal_endpointer_for_end_of_speech = 0;
		val = ast_variable_retrieve(cfg, "general", "use_internal_endpointer_for_end_of_speech");
		if (!ast_strlen_zero(val)) {
			conf->use_internal_endpointer_for_end_of_speech = ast_true(val);
		}
		
		conf->recognition_start_failure_retries = 4;
		val = ast_variable_retrieve(cfg, "general", "recognition_start_failure_retries");
		if (!ast_strlen_zero(val)) {
			int i;
			if (1 == sscanf(val, "%d", &i)) {
				conf->recognition_start_failure_retries = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value '%s' for recognition_start_failure_retries\n", val);
			}
		}

		conf->recognition_start_failure_retry_max_time_ms = 1000;
		val = ast_variable_retrieve(cfg, "general", "recognition_start_failure_retry_max_time_ms");
		if (!ast_strlen_zero(val)) {
			int i;
			if (1 == sscanf(val, "%d", &i)) {
				conf->recognition_start_failure_retry_max_time_ms = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value '%s' for recognition_start_failure_retry_max_time_ms\n", val);
			}
		}
		
		ast_string_field_set(conf, start_failure_retry_codes, ",14,");
		val = ast_variable_retrieve(cfg, "general", "start_failure_retry_codes");
		if (!ast_strlen_zero(val)) {
			ast_string_field_build(conf, start_failure_retry_codes, ",%s,", val);
		}

		val = ast_variable_retrieve(cfg, "general", "model");
		if (!ast_strlen_zero(val)) {
			ast_string_field_set(conf, model, val);
		}

		if (conf->hints) {
			val = ast_variable_retrieve(cfg, "general", "hints");
			if (!ast_strlen_zero(val)) {
				parse_hints(conf->hints, val);
			}
		}

		conf->default_incomplete_timeout = 0;
		val = ast_variable_retrieve(cfg, "general", "default_incomplete_timeout");
		if (!ast_strlen_zero(val)) {
			int i;
			if (1 == sscanf(val, "%d", &i)) {
				conf->default_incomplete_timeout = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value '%s' for default_incomplete_timeout\n", val);
			}
		}

		conf->default_no_speech_timeout = 0;
		val = ast_variable_retrieve(cfg, "general", "default_no_speech_timeout");
		if (!ast_strlen_zero(val)) {
			int i;
			if (1 == sscanf(val, "%d", &i)) {
				conf->default_no_speech_timeout = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value '%s' for default_no_speech_timeout\n", val);
			}
		}

		conf->default_maximum_speech_timeout = 60 * 1000;
		val = ast_variable_retrieve(cfg, "general", "default_maximum_speech_timeout");
		if (!ast_strlen_zero(val)) {
			int i;
			if (1 == sscanf(val, "%d", &i)) {
				conf->default_maximum_speech_timeout = i;
			} else {
				ast_log(LOG_WARNING, "Invalid value '%s' for default_maximum_speech_timeout\n", val);
			}
		}

		category = NULL;
		while ((category = ast_category_browse(cfg, category))) {
			if (strcasecmp("general", category)) {
				const char *name = category;
				const char *project_id = ast_variable_retrieve(cfg, category, "project_id");
				const char *endpoint = ast_variable_retrieve(cfg, category, "endpoint");
				const char *service_key = ast_variable_retrieve(cfg, category, "service_key");
				const char *enable_sentiment_analysis = ast_variable_retrieve(cfg, category, "enable_sentiment_analysis");
				const char *hints = ast_variable_retrieve(cfg, category, "hints");
				const char *use_internal_endpointer_for_end_of_speech_str = ast_variable_retrieve(cfg, category, "use_internal_endpointer_for_end_of_speech");
				const char *model = ast_variable_retrieve(cfg, category, "model");
				int use_internal_endpointer_for_end_of_speech;
				enum SENTIMENT_ANALYSIS_STATE sentiment_analysis_state = SENTIMENT_ANALYSIS_DEFAULT;

				if (!ast_strlen_zero(service_key)) {
					struct ast_str *buffer = load_service_key(service_key);
					if (buffer) {
						service_key = ast_strdupa(ast_str_buffer(buffer));
						ast_free(buffer);
					}
				}

				use_internal_endpointer_for_end_of_speech = conf->use_internal_endpointer_for_end_of_speech;
				if (!ast_strlen_zero(use_internal_endpointer_for_end_of_speech_str)) {
					use_internal_endpointer_for_end_of_speech = ast_true(use_internal_endpointer_for_end_of_speech_str);
				}

				if (!ast_strlen_zero(enable_sentiment_analysis)) {
					if (ast_true(enable_sentiment_analysis) || !strcasecmp(enable_sentiment_analysis, "always")) {
						sentiment_analysis_state = SENTIMENT_ANALYSIS_ALWAYS;
					} else if (!strcasecmp(enable_sentiment_analysis, "default")) {
						sentiment_analysis_state = SENTIMENT_ANALYSIS_DEFAULT;
					} else {
						sentiment_analysis_state = SENTIMENT_ANALYSIS_NEVER;
					}
				}

				if (!ast_strlen_zero(project_id)) {
					struct gdf_logical_agent *agent;
					
					agent = logical_agent_alloc(name, project_id, S_OR(service_key, ""), S_OR(endpoint, ""), sentiment_analysis_state, 
						hints, use_internal_endpointer_for_end_of_speech, S_OR(model, conf->model));
					if (agent) {
						ao2_link(conf->logical_agents, agent);
						ao2_ref(agent, -1);
					} else {
						ast_log(LOG_WARNING, "Memory allocation failed creating logical agent %s\n", name);
					}
				} else {
					ast_log(LOG_WARNING, "Mapped project_id is required for %s\n", name);
				}
			}
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

		if (cfg) {
			ast_config_destroy(cfg);
		}
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
			struct ao2_iterator i;
			struct ao2_iterator h;
			char *hint;
			struct gdf_logical_agent *agent;

			ast_cli(a->fd, "[general]\n");
			ast_cli(a->fd, "service_key = %s\n", config->service_key);
			ast_cli(a->fd, "endpoint = %s\n", config->endpoint);
			ast_cli(a->fd, "vad_voice_threshold = %d\n", config->vad_voice_threshold);
			ast_cli(a->fd, "vad_voice_minimum_duration = %d\n", config->vad_voice_minimum_duration);
			ast_cli(a->fd, "vad_silence_minimum_duration = %d\n", config->vad_silence_minimum_duration);
			ast_cli(a->fd, "vad_barge_minimum_duration = %d\n", config->vad_barge_minimum_duration);
			ast_cli(a->fd, "vad_end_of_speech_silence_duration = %d\n", config->vad_end_of_speech_silence_duration);
			ast_cli(a->fd, "endpointer_cache_audio_pretrigger_ms = %d\n", config->endpointer_cache_audio_pretrigger_ms);
			ast_cli(a->fd, "default_incomplete_timeout = %d\n", config->default_incomplete_timeout);
			ast_cli(a->fd, "default_no_speech_timeout = %d\n", config->default_no_speech_timeout);
			ast_cli(a->fd, "default_maximum_speech_timeout = %d\n", config->default_maximum_speech_timeout);
			ast_cli(a->fd, "call_log_location = %s\n", config->call_log_location);
			ast_cli(a->fd, "enable_call_logs = %s\n", AST_CLI_YESNO(config->enable_call_logs));
			ast_cli(a->fd, "enable_preendpointer_recordings = %s\n", AST_CLI_YESNO(config->enable_preendpointer_recordings));
			ast_cli(a->fd, "enable_postendpointer_recordings = %s\n", AST_CLI_YESNO(config->enable_postendpointer_recordings));
			ast_cli(a->fd, "record_preendpointer_on_demand = %s\n", AST_CLI_YESNO(config->record_preendpointer_on_demand));
			ast_cli(a->fd, "enable_sentiment_analysis = %s\n", config->enable_sentiment_analysis == SENTIMENT_ANALYSIS_ALWAYS ? "always" :
																config->enable_sentiment_analysis == SENTIMENT_ANALYSIS_DEFAULT ? "default" : "never");
			ast_cli(a->fd, "stop_writes_on_final_transcription = %s\n", AST_CLI_YESNO(config->stop_writes_on_final_transcription));
			ast_cli(a->fd, "start_recognition_on_start = %s\n", AST_CLI_YESNO(config->start_recognition_on_start));
			ast_cli(a->fd, "recognition_start_failure_retries = %d\n", config->recognition_start_failure_retries);
			ast_cli(a->fd, "recognition_start_failure_retry_max_time_ms = %d\n", config->recognition_start_failure_retry_max_time_ms);
			ast_cli(a->fd, "start_failure_retry_codes = %s\n", config->start_failure_retry_codes);
			ast_cli(a->fd, "synthesize_fulfillment_text = %s\n", AST_CLI_YESNO(config->synthesize_fulfillment_text));
			ast_cli(a->fd, "model = %s\n", config->model);
			ast_cli(a->fd, "use_internal_endpointer_for_end_of_speech = %s\n", AST_CLI_YESNO(config->use_internal_endpointer_for_end_of_speech));
			ast_cli(a->fd, "hints = ");
			h = ao2_iterator_init(config->hints, 0);
			while ((hint = ao2_iterator_next(&h))) {
				ast_cli(a->fd, "%s, ", hint);
				ao2_ref(hint, -1);
			}
			ast_cli(a->fd, "\n");
			ao2_iterator_destroy(&h);
			i = ao2_iterator_init(config->logical_agents, 0);
			while ((agent = ao2_iterator_next(&i))) {
				ast_cli(a->fd, "\n[%s]\n", agent->name);
				ast_cli(a->fd, "project_id = %s\n", agent->project_id);
				ast_cli(a->fd, "endpoint = %s\n", agent->endpoint);
				ast_cli(a->fd, "service_key = %s\n", agent->service_key);
				ast_cli(a->fd, "model = %s\n", agent->model);
				ast_cli(a->fd, "use_internal_endpointer_for_end_of_speech = %s\n", AST_CLI_YESNO(agent->use_internal_endpointer_for_end_of_speech));
				ast_cli(a->fd, "enable_sentiment_analysis = %s\n", agent->enable_sentiment_analysis == SENTIMENT_ANALYSIS_ALWAYS ? "always" :
																	agent->enable_sentiment_analysis == SENTIMENT_ANALYSIS_DEFAULT ? "default" : "never");
				ast_cli(a->fd, "hints = ");
				h = ao2_iterator_init(agent->hints, 0);
				while ((hint = ao2_iterator_next(&h))) {
					ast_cli(a->fd, "%s, ", hint);
					ao2_ref(hint, -1);
				}
				ast_cli(a->fd, "\n");
				ao2_iterator_destroy(&h);
				ao2_ref(agent, -1);
			}
			ao2_iterator_destroy(&i);
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

static int call_log_enabled_for_pvt(struct gdf_pvt *pvt)
{
	struct gdf_config *config;
	int log_enabled = 0;
	
	config = gdf_get_config();
	if (config) {
		log_enabled = config->enable_call_logs;
		if (log_enabled) {
			ao2_lock(pvt);
			log_enabled = (pvt->call_log_file_handle != NULL);
			ao2_unlock(pvt);
		}

		ao2_t_ref(config, -1, "done with config in log check");
	}
	return log_enabled;
}

#ifndef ASTERISK_13_OR_LATER
#define AST_ISO8601_LEN	29
#endif

static void gdf_log_call_event(struct gdf_pvt *pvt, struct gdf_request *req, enum gdf_call_log_type type, const char *event, size_t log_data_size, const struct dialogflow_log_data *log_data)
{
	struct timeval timeval_now;
	struct ast_tm tm_now = {};
	char char_now[AST_ISO8601_LEN];
	const char *char_type;
	char *log_line;
	size_t i;
#ifdef ASTERISK_13_OR_LATER
	RAII_VAR(struct ast_json *, log_message, ast_json_object_create(), ast_json_unref);
#else
	json_t *log_message;
#endif

	if (!call_log_enabled_for_pvt(pvt)) {
		return;
	}
    
	timeval_now = ast_tvnow();
	ast_localtime(&timeval_now, &tm_now, NULL);

	ast_strftime(char_now, sizeof(char_now), "%FT%T.%q%z", &tm_now);

	if (type == CALL_LOG_TYPE_SESSION) {
		char_type = "SESSION";
	} else if (type == CALL_LOG_TYPE_RECOGNITION) {
		char_type = "RECOGNITION";
	} else if (type == CALL_LOG_TYPE_ENDPOINTER) {
		char_type = "ENDPOINTER";
	} else if (type == CALL_LOG_TYPE_DIALOGFLOW) {
		char_type = "DIALOGFLOW";
	} else {
		char_type = "UNKNOWN";
	}

#ifdef ASTERISK_13_OR_LATER
	ast_json_object_set(log_message, "log_timestamp", ast_json_string_create(char_now));
	ast_json_object_set(log_message, "log_type", ast_json_string_create(char_type));
	ast_json_object_set(log_message, "log_event", ast_json_string_create(event));
	for (i = 0; i < log_data_size; i++) {
		if (log_data[i].value_type == dialogflow_log_data_value_type_string) {
			ast_json_object_set(log_message, log_data[i].name, ast_json_string_create((const char *)log_data[i].value));
		} else if (log_data[i].value_type == dialogflow_log_data_value_type_array_of_string) {
			size_t j;
			RAII_VAR(struct ast_json *, array, ast_json_array_create(), ast_json_unref);

			for (j = 0; j < log_data[i].value_count; j++) {
				ast_json_array_append(log_message, ast_json_string_create(((const char **)log_data[i].value)[j]));
			}
			ast_json_object_set(log_message, log_data[i].name, ast_json_ref(array));
		}
	}
	log_line = ast_json_dump_string(log_message);
#else
	log_message = json_object();
	json_object_set_new(log_message, "log_timestamp", json_string(char_now));
	json_object_set_new(log_message, "log_type", json_string(char_type));
	json_object_set_new(log_message, "log_event", json_string(event));
	if (req) {
		json_object_set_new(log_message, "request_number", json_integer(req->current_utterance_number));
	}
	for (i = 0; i < log_data_size; i++) {
		if (log_data[i].value_type == dialogflow_log_data_value_type_string) {
			json_object_set_new(log_message, log_data[i].name, json_string((const char *)log_data[i].value));
		} else if (log_data[i].value_type == dialogflow_log_data_value_type_array_of_string) {
			size_t j;
			json_t *array = json_array();

			for (j = 0; j < log_data[i].value_count; j++) {
				json_array_append_new(array, json_string(((const char **)log_data[i].value)[j]));
			}
			json_object_set_new(log_message, log_data[i].name, array);
		}
	}
	log_line = json_dumps(log_message, JSON_COMPACT | JSON_PRESERVE_ORDER);
#endif

	ao2_lock(pvt);
	fprintf(pvt->call_log_file_handle, "%s\n", log_line);
	fflush(pvt->call_log_file_handle);
	ao2_unlock(pvt);

#ifdef ASTERISK_13_OR_LATER
	ast_json_free(log_line);
#else
	json_decref(log_message);
	ast_free(log_line);
#endif
}

static void libdialogflow_general_logging_callback(enum dialogflow_log_level level, 
	const char *file, int line, const char *function, const char *fmt, va_list args)
	__attribute__ ((format(printf, 5, 0)));

static void libdialogflow_general_logging_callback(enum dialogflow_log_level level, 
	const char *file, int line, const char *function, const char *fmt, va_list args)
{
	size_t len;
	char *buff;
	va_list args2;
	va_copy(args2, args);
    len = vsnprintf(NULL, 0, fmt, args2);
    va_end(args2);
    buff = alloca(len + 1);
    vsnprintf(buff, len + 1, fmt, args);

	ast_log((int) level, file, line, function, "%s", buff);
}

static void libdialogflow_call_logging_callback(void *user_data, const char *event, size_t log_data_size, const struct dialogflow_log_data *data)
{
	struct gdf_request *req = (struct gdf_request *) user_data;
	gdf_log_call_event(req->pvt, req, CALL_LOG_TYPE_DIALOGFLOW, event, log_data_size, data);
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
#ifdef AST_SPEECH_HAVE_GET_SETTING
	.get_setting = gdf_get_setting,
#endif
	.change_results_type = gdf_change_results_type,
	.get = gdf_get_results,
};

#ifndef ASTERISK_13_OR_LATER
static void *json_custom_malloc(size_t sz)
{
	return ast_malloc(sz);
}
static void json_custom_free(void *ptr)
{
	ast_free(ptr);
}
#endif

#pragma GCC diagnostic ignored "-Wmissing-format-attribute"
static enum ast_module_load_result load_module(void)
{
	struct gdf_config *cfg;

#ifndef ASTERISK_13_OR_LATER
	json_set_alloc_funcs(json_custom_malloc, json_custom_free);
#endif

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
	gdf_engine.formats = AST_FORMAT_SLINEAR;
#endif

	if (ast_speech_register(&gdf_engine)) {
		ast_log(LOG_WARNING, "DFE speech failed to register with speech subsystem\n");
		ao2_ref(config, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	if (df_init(libdialogflow_general_logging_callback, libdialogflow_call_logging_callback)) {
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