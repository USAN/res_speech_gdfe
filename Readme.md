# Configuration

## Default Configuration

### res_speech_gdfe.conf

The configuration for the Google DFE speech module is in the `res_speech_gdfe.conf` file in the Asterisk configuration directory. It is a standard format Asterisk configuration file.

#### [general] section
- `service_key` - (required) the path to a JSON-format Google service key or the actual key itself.
- `endpoint` - (optional) the URL for the DialogFlow API endpoint. Leave blank to use the default `dialogflow.googleapis.com`.
- `vad_voice_threshold` - (optional) the average absolute amplitude of a packet to consider that packet to be 'voice'. The default is 512. Valid range 0-32767.
- `vad_voice_minimum_duration` - (optional, milliseconds) the cumulative duration of consecutive 'voice' packets to consider the caller to be speaking. The default is 40 (milliseconds). Valid range 0-2147483647.
- `vad_silence_minimum_duration` - (optional, milliseconds, not implemented) the cumulative duration of consecutive non-'voice' packets to consider the caller to be not speaking. The default is 500 (milliseconds). Valid range 0-2147483647. This setting currently has no effect as the end of speech is determined by DialogFlow.

### Environment Variables

#### http_proxy

To access the DialogFlow endpoint via a proxy you must set the environment variable `http_proxy` to the URL of your proxy. This must be done for the Asterisk process as a whole.

## Per-Call Configuration

Speech module behavior may be modified by using the `SPEECH_ENGINE` dialplan function. Available settings are:

- `session_id` - set a session identifier to use when making DialogFlow API calls. This will be reflected in the history of the agent on the DialogFlow console. A default random value will be used if not provided.
- `project_id` - set the project identifier to use when making DialogFlow API calls. This setting is required in order to determine which agent to use.
- `language` - set the language for the recognition engine for when doing intent detection and prompt generation. The default is `en`. The engine has no visibility into the channel language -- if it has changed it is still necessary to set the engine language.
- `voice_threshold` - set the average absolute amplitude of a packet to consider that packet to be 'voice' (see `vad_voice_threshold`, above).
- `voice_duration` - set the cumulative duration of consecutive 'voice' packets to consider the caller to be speaking (see `vad_voice_minimum_duration`, above).
- `silence_duration` - the cumulative duration of consecutive non-'voice' packets to consider the caller to be not speaking (see `vad_silence_minimum_duration`, above).

# Usage

## Setup

Before detecting intent for your calls, you must first:
1. create the speech resource (only do this once),
1. set the `project_id`, and

```
same =>   n,SpeechCreate()
same =>   n,Set(SPEECH_ENGINE(project_id)=my-project-12345)
```

## Detecting Intent from Voice

To detect intent from voice, you should call `SpeechBackground` to send audio to the module. You may specify a prompt to play while performing the detection.

```
same =>   n,SpeechBackground(hello-world)
```

## Detecting Intent by Event

To detect intent by event, you should activate a grammar with the name `event:{your event name}` prior to calling `SpeechBackground`. The `SpeechBackground` application will return immediately -- you should not include a prompt.

```
same =>   n,SpeechActivateGrammar(event:welcome)
same =>   n,SpeechBackground(hello-world)
```

## Processing results

The DialogFlow module returns the following results (when available):
- `response_id` - the unique identifier for this response
- `query_text` - the text of the speech recognized by DialogFlow
- `language_code` - the detected language of the recognized speech
- `action` - the action for the detected intent
- `fulfillment_text` - the text of the next prompt for the caller
- `intent_name` - the API name of the intent detected
- `intent_display_name` - the displayed name of the intent detected
- `raw_score` - the raw recognition score
- `fulfillment_message_N_text_M` - the fulfillment text messages from the response
- `fulfillment_message_N_simple_response_M` - the simple response fulfillment messages from the response
- `fulfillment_message_N_telephony_play_audio` - a URI from the telephony audio response fulfillment message
- `fulfillment_message_N_telephony_synthesize_speech` - text or SSML from the telephony synthesized speech fulfillment message
- `fulfillment_message_N_telephony_transfer_call` - a phone number for transferring from the telephony transfer call fulfillment message
- `fulfillment_message_N_telephony_terminate_call` - a flag indicating that the fulfillment message requested call termination
- `fulfillment_audio` - a path to audio corresponding to the fulfillment text

(those with _N_ or _M_ in the name may occur multiple times with different indexes in those positions)

