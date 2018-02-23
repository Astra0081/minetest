#include <cassert>
#include <condition_variable>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <espeak-ng/espeak_ng.h>

#include <config.h>
#include <filesys.h>
#include <porting.h>
#include <sound.h>
#include <sound_espeakng.h>

std::shared_ptr<MtESpeak> g_espeak;

static void throw_if_error()
{
	if (alGetError() != AL_NO_ERROR)
		throw std::runtime_error("espeak OpenAL error");
}

static int mt_espeak_callback(short *wav, int numsamples, espeak_EVENT *events)
{
	MtESpeakData *data = (MtESpeakData *) events->user_data;

	if (wav == NULL)
		return 0;

	data->m_buf.append((const char *) wav, numsamples * 2);

	return 0;
}

MtESpeak::MtESpeak() :
	m_thread(),
	m_mutex(),
	m_request_queue_cv(),
	m_request_queue(),
	m_data_path(),
	m_source(-1),
	m_buffer(-1),
	m_sample_rate(0)
{
	ALuint source = -1;
	ALuint buffer = -1;

	assert(alcGetCurrentContext() != NULL);

	alGenSources(1, &source);
	alGenBuffers(1, &buffer);

	throw_if_error();

	/* minetest will screw with alDistanceModel, alListener(AL_POSITION..) etc
	   which are meant for the 3D sounds within the game - we negate influence by forcing gain */
	alSourcef(source, AL_MIN_GAIN, 1.0f);
	alSourcef(source, AL_MAX_GAIN, 1.0f);

	throw_if_error();

	std::string data_subpath = std::string("client") + DIR_DELIM + "espeak-ng-data";
	std::string data_subpath_checkfile = data_subpath + DIR_DELIM + "en_dict";
	std::string data_path_checkfile = porting::getDataPath(data_subpath_checkfile.c_str());
	std::string data_path = porting::getDataPath(data_subpath.c_str());

	if (! fs::PathExists(data_path_checkfile))
		throw std::runtime_error("espeak check");

	int rate = espeak_Initialize(AUDIO_OUTPUT_SYNCHRONOUS, 0, data_path.c_str(), 0);
	if (rate == -1)
		throw std::runtime_error("espeak initialize");
	espeak_SetSynthCallback(mt_espeak_callback);

	m_data_path = data_path;
	m_source = source;
	m_buffer = buffer;
	m_sample_rate = rate;
}

MtESpeak::~MtESpeak()
{
	requestEnqueueExit();

	if (m_thread.joinable())
		join();
}

void MtESpeak::start()
{
	m_thread = std::thread(&MtESpeak::threadFunc, this);
}

void MtESpeak::join()
{
	m_thread.join();

	if (m_thread_exc) {
		try {
			std::rethrow_exception(m_thread_exc);
		}
		catch (const std::exception &e) {
			throw e;
		}
	}
}

void MtESpeak::requestEnqueueExit()
{
	MtESpeakRequest req;
	req.m_type = MT_ESPEAK_REQUEST_TYPE_EXIT;
	requestEnqueue(std::move(req));
}

void MtESpeak::requestEnqueueText(const std::string &text)
{
	MtESpeakRequest req;
	req.m_type = MT_ESPEAK_REQUEST_TYPE_TEXT;
	req.m_text = text;
	requestEnqueue(std::move(req));
}

void MtESpeak::requestEnqueue(MtESpeakRequest req)
{
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		m_request_queue.push_back(std::move(req));
	}
	m_request_queue_cv.notify_one();
}

void MtESpeak::threadFunc()
{
	try {
		threadFunc2();
	}
	catch (const std::exception &e) {
		m_thread_exc = std::current_exception();
	}
}

void MtESpeak::threadFunc2()
{
	while (true) {
		std::unique_lock<std::mutex> lock(m_mutex);
		m_request_queue_cv.wait(lock, [&]() { return ! m_request_queue.empty(); });

		MtESpeakRequest req = std::move(m_request_queue.front());
		m_request_queue.pop_front();

		switch (req.m_type)
		{
		case MT_ESPEAK_REQUEST_TYPE_EXIT:
		{
			return;
		}
		break;

		case MT_ESPEAK_REQUEST_TYPE_TEXT:
		{
			std::string text = req.m_text;

			lock.unlock();

			MtESpeakData data;

			if (espeak_Synth(text.c_str(), text.size(), 0, POS_CHARACTER, 0, 0, NULL, &data) != EE_OK)
				throw std::runtime_error("espeak synth");

			alSourceStop(m_source);
			throw_if_error();
			alSourcei(m_source, AL_BUFFER, AL_NONE);
			throw_if_error();

			alBufferData(m_buffer, AL_FORMAT_MONO16, data.m_buf.data(), data.m_buf.size(), m_sample_rate);
			throw_if_error();

			alSourcei(m_source, AL_BUFFER, m_buffer);
			throw_if_error();

			alSourcePlay(m_source);
			throw_if_error();

			while (true) {
				int state = -1;
				alGetSourcei(m_source, AL_SOURCE_STATE, &state);
				throw_if_error();
				if (state != AL_PLAYING)
					break;
			}
		}
		break;

		default:
			assert(0);
		}
	}
}

std::shared_ptr<MtESpeak> createESpeakGlobal()
{
#ifdef USE_ESPEAKNG
	std::shared_ptr<MtESpeak> espeak(new MtESpeak());
	espeak->start();
#else
	std::shared_ptr<MtESpeak> espeak;
#endif
	return espeak;
}
