#include <iostream>
#include <fstream>
#include <streambuf>
#include <mutex>
#include <string>
#include <string_view>
#include <chrono>
#include <filesystem>
#include <cassert>
#include <thread>
#include <sstream>
/*
// CSimpleLogger.h
//
// ���˼·��
// ����򵥵���־ϵͳּ���ṩһ�����ķ�ʽ��¼��־��֧�ֶ��̻߳����µİ�ȫ��־��¼��
// �����Ը�����Ҫѡ���Ƿ����û���XOR�ļ򵥼��ܹ��ܡ����⣬��ϵͳ��֧����־�ļ����Զ��ֻ������ﵽָ����Сʱ�ᴴ���µ���־�ļ���
//
// ʹ��ϸ�ڣ�
// 1. ��־���𣺶��������ֻ�������־������Ϣ�����桢���󣩣�����ͨ��ö���� LogLevel ��ָ����
// 2. ��־��������ṩ�� CLogStream ��ģ�壬���ڹ���һ����־��Ϣ���û�����ͨ����ʽ�ӿ�
//    ����Ϣ���ӵ���ǰ����־��Ŀ�С�
// 3. ��־�ࣺCSimpleLogger ��һ��ģ���࣬�����û�������Ҫѡ���Ƿ����ü����Լ��Ƿ�֧�ֶ��̡߳�
// 4. ��־�ļ�����֧����־�ļ�������С������ļ��������ã����ﵽ����ֵʱ���Զ�������־�ļ��ֻ���
// 5. ʱ������߳�ID��ÿ����־��Ŀ�������ʱ����ͼ�¼��־ʱ���ڵ��߳�ID��
// 6. �ļ�·�������Զ���ȡ����¼��־���λ�õ��ļ������кš�
// 7. �ַ����ͣ�ͨ��Ԥ����� LOG_USE_WCHAR ����ѡ��ʹ�ÿ��ַ�����ͨ�ַ���
// 7. �����С�Ĵ�����Ǹ߿���չ�ԡ�ʹ���߿��԰����޸�Դ�룬ʵ�������־��ʽ���Զ��壬�����㷨��ѹ���㷨ʵ�ּ��ܺ�ѹ���ȡ�
//
// ʾ���÷���
// CSimpleLogger<> logger("example_log", 1024 * 1024 * 20, 5); // ����һ����־ʵ�������20MB����ౣ��5����־�ļ�
// SIMPLE_LOG_INFO(logger) << "This is an info message.";
// SIMPLE_LOG_WARNING(logger) << "This is a warning message.";
// SIMPLE_LOG_ERROR(logger) << "This is an error message.";
//
// ���������֧�� C++20��
// SIMPLE_LOG_INFO_FMT(logger, "{} message.", "Info");
// SIMPLE_LOG_WARNING_FMT(logger, "{} message.", "Warning");
// SIMPLE_LOG_ERROR_FMT(logger, "{} message.", "Error");
//
// ע�����
// - ��־��¼����Ĭ��Ϊ�̰߳�ȫ���������Ҫ�̰߳�ȫ�������ڴ�����־����ʱָ����
// - ��־�ļ������ƺ�·��Ӧ�þ����㹻��Ȩ�����������ж�д������
// - ��־��¼���ܻ����Ľ϶�Ĵ��̿ռ䣬�ر����ڸ�������Ӧ�ó����¡�
// - ��������˼��ܹ��ܣ���ȷ�����ʵ��ķ���������־�ļ��Ա��ں����鿴�������
// - CSimpleLogger��CQueuedLogger�Ĳ��죺
//       0. CSimpleLogger����ʹ����д����־ʱд���ļ��ͼ���/ѹ����CQueuedLogger����־����ר�ŵ���־�߳�д���ļ��ͼ���/ѹ����
//       1. CSimpleLogger�ʺ��ڴ󲿷ֵĳ�����ʹ�ü򵥿ɿ������ܸߡ�
//       2. ���������ر����У���־���ر��ʹ���߶���־���õ�ʱ��Ҫ�󼫸ߵĳ���������ʹ��CQueuedLogger��
//       3. CQueuedLogger���ŵ����ѡ����ʵ�Queued��С���Ϳ�������������������ʹ���ߡ�
//       4. ���⣬���ڸ��Ӽ��ܺ�ѹ���ĳ�����CQueuedLogger������Ҳ���ã���Ϊѹ���߼��ڶ����߳���ɣ���Ӱ��ʹ���ߡ�
//       5. CQueuedLogger��ȱ������Ҫ��������һ���߳���Դ��
//
// - ����־ϵͳ�Ĵ���������������ˣ�ʹ���û��ܹ�����������ڲ��߼������������չ��ͨ��������Ĺ��ܣ�����������ά���ɱ�����Ϊ�û��ṩ�˹㷺���Զ���ռ䡣
//   ʹ���߿��Ը����Լ������������޸�Դ�룬ʵ�ֶ���־�����ʽ�Ķ��ƣ��������ʱ�����ʽ�����Ӷ������Ϣ�ֶεȡ����⣬�����㷨��ѹ���㷨��ʵ��Ҳ�����ڴ˻����Ͻ�����չ������Ӧ��ͬ��Ӧ�ó���������������ݽ��м��ܱ�����Դ�����־���ݽ���ѹ���洢���Ӷ���ߴ洢Ч�ʺͰ�ȫ�ԡ�
*/

// ͨ������SLOG_CONFIG_USE_WCHAR=1ʹ��wchar_t�汾��Ĭ��Ϊchar��
#ifndef SLOG_CONFIG_USE_WCHAR
#define SLOG_CONFIG_USE_WCHAR 0
#endif

#define SLOG_CONFIG_ENCRYPTION_XOR_KEY 'L' // ������Կ

namespace SLog {

#if SLOG_CONFIG_USE_WCHAR
#define SLOG_CONFIG_FILE_SUFFIX L".log" // ��־�ļ���׺
	typedef wchar_t Char;
	typedef std::char_traits<Char>::int_type CharInt;
	typedef std::wstreambuf StringBuf;
	typedef std::wfilebuf FileBuffer;
	typedef std::wostringstream OutputStream;
	typedef std::wostream OutputStreamType;
	typedef std::wstring StringType;
	typedef std::wstring_view StringView;
	typedef std::wstringstream StringStream;
	inline StringType numberToString(std::size_t n) {
		return std::to_wstring(n);
	}
#define SLOG_LITERAL(x) L ## x
#define SLOG_LITERAL1(x) SLOG_LITERAL(x)
#define __SLOG_FILE__ SLOG_LITERAL1(__FILE__)

#else
#define SLOG_CONFIG_FILE_SUFFIX ".log" // ��־�ļ���׺
	typedef char Char;
	typedef std::char_traits<Char>::int_type CharInt;
	typedef std::streambuf StringBuf;
	typedef std::filebuf FileBuffer;
	typedef std::ostringstream OutputStream;
	typedef std::ostream OutputStreamType;
	typedef std::string StringType;
	typedef std::string_view StringView;
	typedef std::stringstream StringStream;
	inline StringType numberToString(std::size_t n) {
		return std::to_string(n);
	}
#define SLOG_LITERAL(x) x
#define __SLOG_FILE__ __FILE__
#endif



	namespace SimpleLogEncryption {


		template<bool enableEncryption>
		class XOREncryptionBuffer : public StringBuf {
		public:
			XOREncryptionBuffer(Char key) : encryptionKey(key) {}
		protected:

			// ��־��������߼��������Ҫ���ƻ������߼�������ѹ���߼����޸���overflow��xsputn�������������ɡ������XOR�����߼���������һ��ʾ����

			virtual CharInt overflow(CharInt ch) override {
				if (!enableEncryption) {
					return fileBuffer.sputc(ch);
				}
				else {
					return fileBuffer.sputc(static_cast<Char>(ch) ^ encryptionKey);
				}
				return ch;
			}


			virtual std::streamsize xsputn(const Char* s, std::streamsize count) override {
				if (!enableEncryption) {
					return fileBuffer.sputn(s, count);
				}
				else {
					std::basic_string<Char> temp;
					temp.reserve(count);
					for (std::streamsize i = 0; i < count; ++i) {
						temp.push_back(s[i] ^ encryptionKey);
					}
					return fileBuffer.sputn(temp.data(), temp.size());
				}
			}


		public:
			FileBuffer fileBuffer;


		private:
			Char encryptionKey;
		};


		template<bool enableEncryption>
		class LogOutStream : public OutputStreamType {
		public:
			LogOutStream()
				: OutputStreamType(&streamBuf),
				streamBuf(SLOG_CONFIG_ENCRYPTION_XOR_KEY) {}


			bool is_open() {
				return streamBuf.fileBuffer.is_open();
			}
			void close() {
				streamBuf.fileBuffer.close();
			}
			int open(const StringType& FileName, int OpenFlag) {
				return streamBuf.fileBuffer.open(FileName.c_str(), OpenFlag) != nullptr;
			}
			long long tellp() {
				return streamBuf.fileBuffer.pubseekoff(0, std::ios_base::cur, std::ios_base::out);
			}


		private:
			XOREncryptionBuffer<enableEncryption> streamBuf;
		};
	}


	enum class LogLevel { INFO, WARNING, ERROR };


	template <class CLogger>
	class CLogStream {
	public:
		CLogStream(CLogger& logger, LogLevel level, const Char* file, int line)
			: logger(logger) {
			logger.onStartLogItem();
			// ��־��ʽ�������߼��������Ҫ���ƻ���ʽ���������޸��ⲿ�ִ��뼴�ɡ�
			logger.stream() << logLevelToString(level) << std::this_thread::get_id();
			printCurrentTime(logger.stream());
			//logger.stream() << extractFilename(file).data() << SLOG_LITERAL("@") << line << SLOG_LITERAL(": ");
		}


		~CLogStream() {
			logger.stream() << std::endl; // ����
			logger.onEndLogItem();
		}


		template<typename T>
		CLogStream& operator<<(const T& msg) {
			logger.stream() << msg;
			return *this;
		}


		CLogStream(const CLogStream&) = delete;
		CLogStream& operator=(const CLogStream&) = delete;


	private:
		inline StringView extractFilename(const StringView& path) const {
#ifdef _WIN32
			auto path_separator = SLOG_LITERAL('\\');
#else
			auto path_separator = SLOG_LITERAL('/');
#endif
			size_t pos = path.find_last_of(path_separator);
			if (pos != StringView::npos) {
				return path.substr(pos + 1);
			}
			return std::move(path);
		}


		template<class StreamType>
		inline void printCurrentTime(StreamType& stream) {
			auto now = std::chrono::system_clock::now();
			std::time_t now_time = std::chrono::system_clock::to_time_t(now);
			std::tm now_tm = {};
#ifdef _WIN32
			if (localtime_s(&now_tm, &now_time) == 0) {
#else
			if (localtime_r(&now_time, &now_tm)) {
#endif // _WIN32
				long long now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
				char buffer[32];
				std::snprintf(buffer, sizeof(buffer), " %04d-%02d-%02d %02d:%02d:%02d.%03d\t",
					now_tm.tm_year + 1900, now_tm.tm_mon + 1, now_tm.tm_mday,
					now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, (int)(now_ms % 1000));
				stream << buffer;
			}
			else {
				assert(false);
			}
			}


		inline const char* logLevelToString(LogLevel level) const {
			switch (level) {
			case LogLevel::INFO:
				return "INFO ";
			case LogLevel::WARNING:
				return "WARN ";
			case LogLevel::ERROR:
				return "ERRO ";
			default:
				return "UNKNOWN ";
			}
		}


	private:
		CLogger& logger;
		};


	template<bool enableEncryption = false, bool bSupportMulitThread = true>
	class CSimpleLogger {
	public:
		CSimpleLogger(const StringType& filename, size_t maxSize = 20 * 1024 * 1024, size_t maxFiles = 4)
			: log_file_prefix(filename),
			max_file_size(maxSize),
			max_files(maxFiles) {
			initializeLoggerWithOutLock();
		}


		~CSimpleLogger() {
			if (log_stream.is_open()) {
				log_stream.close();
			}
		}


		auto log(LogLevel level, const Char* file, int line) {
			return CLogStream<CSimpleLogger>(*this, level, file, line);
		}


		void onStartLogItem() {
			if (bSupportMulitThread) {
				log_mutex.lock();
			}
		}


		void onEndLogItem() {
			checkAndRotateWithOutLock();
			if (bSupportMulitThread) {
				log_mutex.unlock();
			}
		}


		auto& stream() {
			return this->log_stream;
		}


	private:
		SimpleLogEncryption::LogOutStream<enableEncryption> log_stream;


	private:
		std::mutex log_mutex;
		StringType log_file_prefix;
		size_t max_file_size;
		size_t max_files;


		void initializeLoggerWithOutLock() {
			try {
				if (log_stream.is_open()) {
					log_stream.close();
				}
				log_stream.open(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX, std::ios::app);
				for (int i = 0; !log_stream.is_open(); ++i) {
					log_stream.open(log_file_prefix + SLOG_LITERAL(".") + numberToString(i) + SLOG_LITERAL(".temp") + SLOG_CONFIG_FILE_SUFFIX, std::ios::app);
				}
			}
			catch (...) {
				assert(false);
			}
		}


		void rotateLogsWithOutLock() {
			try {
				log_stream.close();
				if (std::filesystem::exists(log_file_prefix + SLOG_LITERAL(".") + numberToString(max_files) + SLOG_CONFIG_FILE_SUFFIX)) {
					std::filesystem::remove(log_file_prefix + SLOG_LITERAL(".") + numberToString(max_files) + SLOG_CONFIG_FILE_SUFFIX);
				}
				for (size_t i = max_files; i > 1; --i) {
					auto src = log_file_prefix + SLOG_LITERAL(".") + numberToString(i - 1) + SLOG_CONFIG_FILE_SUFFIX;
					auto dst = log_file_prefix + SLOG_LITERAL(".") + numberToString(i) + SLOG_CONFIG_FILE_SUFFIX;
					if (std::filesystem::exists(src)) {
						std::filesystem::rename(src, dst);
					}
				}
				if (std::filesystem::exists(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX)) {
					std::filesystem::rename(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX, log_file_prefix + SLOG_LITERAL(".1") + SLOG_CONFIG_FILE_SUFFIX);
				}
			}
			catch (...) {
				assert(false);
			}
		}


		void checkAndRotateWithOutLock() {
			if (log_stream.tellp() >= static_cast<std::streamoff>(max_file_size)) {
				rotateLogsWithOutLock();
				initializeLoggerWithOutLock();
			}
		}
	};


	//


	// �̶߳��а汾����־��
	// ԭ��ʹ��������������ģ�ͣ�д����־����һ���̡߳�д����־�ĵ��ÿ��Է��طǳ��죬���ʹ�������ܡ�ͨ������queuedSize���Ի��һ���ڴ������ƽ�����Ѳ�����
	template<bool enableEncryption = false, int queuedSize = 500>
	class CQueuedLogger {
	private:
		template <typename T> class CProducerConsumer {
		public:
			CProducerConsumer(int max_capacity = 10) : capacity(max_capacity) {};
			void produce(T value) {
				std::unique_lock<std::mutex> lock(mtx);
				while (buffer.size() == capacity) { // ������������ˣ���ȴ�
					cond_var.wait(lock);
				}
				buffer.push_back(std::move(value));
				cond_var.notify_one(); // ֪ͨ������
			}


			void consume(std::vector<T>& out) {
				std::unique_lock<std::mutex> lock(mtx);
				while (buffer.empty()) { // ���������Ϊ�գ���ȴ�
					cond_var.wait(lock);
				}
				assert(out.empty());
				std::swap(out, buffer);//ֱ�Ӱ�����buffer������
				cond_var.notify_one(); // ֪ͨ������
			}


		private:
			std::vector<T> buffer;
			const size_t capacity = 10; // ����������
			std::mutex mtx;
			std::condition_variable cond_var;
		};


	public:
		CQueuedLogger(const StringType& filename, size_t maxSize = 20 * 1024 * 1024, size_t maxFiles = 4) :
			m_singleThreadLoger(filename, maxSize, maxFiles),
			producerConsumer(queuedSize),
			write_log_thread([this]() {this->logThreadProc(); }) {
		}


		~CQueuedLogger() {
			need_exit_log_thread = true;
			write_log_thread.join();
		}


		// �����public��Log�ӿڣ�ЭԼʽ��� ����ʵ��
		inline auto log(LogLevel level, const Char* file, int line) {
			return CLogStream<CQueuedLogger>(*this, level, file, line);
		}


		void onStartLogItem() {
		}


		void onEndLogItem() {
			// �����stream����
			producerConsumer.produce(stream().str());
			stream().str(StringType());//���
		}


		auto& stream() {
			static thread_local StringStream log_stream;
			return log_stream;
		}
	private:


		void logThreadProc() {
			while (need_exit_log_thread == false) {
				m_singleThreadLoger.onStartLogItem();
				std::vector<StringType> logs;
				producerConsumer.consume(logs);
				for (auto it = logs.begin(); it != logs.end(); ++it) {
					m_singleThreadLoger.stream() << *it;
					//m_singleThreadLoger.onEndLogItem(); onEndLogItemӦ��Ҫ��������ã���������Ϊ��׷����ߵ����ܣ�ѡ�������á�
				}
				m_singleThreadLoger.onEndLogItem();
			}
		}


	private:
		CSimpleLogger<enableEncryption, false> m_singleThreadLoger;
		CProducerConsumer<StringType> producerConsumer;
		std::thread write_log_thread;
		bool need_exit_log_thread = false;
	};


	}



// �������Զ�����ļ������к�
#define SIMPLE_LOG_INFO(logger) logger.log(LogLevel::INFO, __SLOG_FILE__, __LINE__)
#define SIMPLE_LOG_WARNING(logger) logger.log(LogLevel::WARNING, __SLOG_FILE__, __LINE__)
#define SIMPLE_LOG_ERROR(logger) logger.log(LogLevel::ERROR, __SLOG_FILE__, __LINE__)


#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
#include <format>
// ʹ�� std::format ʵ�ָ�ʽ����־��¼
#define SIMPLE_LOG_INFO_FMT(logger, fmt, ...) SIMPLE_LOG_INFO(logger) << std::format(fmt, __VA_ARGS__)
#define SIMPLE_LOG_WARNING_FMT(logger, fmt, ...) SIMPLE_LOG_WARNING(logger) << std::format(fmt, __VA_ARGS__)
#define SIMPLE_LOG_ERROR_FMT(logger, fmt, ...) SIMPLE_LOG_ERROR(logger) << std::format(fmt, __VA_ARGS__)
#endif




//
using namespace SLog;

void logMessages(CSimpleLogger<false, true>& logger, int thread_id, int message_count) {
	for (int i = 0; i < message_count / 3; ++i) {
		SIMPLE_LOG_INFO(logger) << SLOG_LITERAL("Thread ") << thread_id << SLOG_LITERAL(" logging message ") << i;
		SIMPLE_LOG_WARNING(logger) << SLOG_LITERAL("Test Warning") << i;
		SIMPLE_LOG_ERROR(logger) << SLOG_LITERAL("Test Error") << i;

#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
		SIMPLE_LOG_INFO_FMT(logger, SLOG_LITERAL("fmt log: {}"), i); // c++ 20 ֧��
#endif
	}
	std::cout << std::chrono::system_clock::now() << " ## logMessages threadid:" << thread_id << " Done!\n";
}


void logMessagesQueued(CQueuedLogger<false>& logger, int thread_id, int message_count) {
	for (int i = 0; i < message_count / 3; ++i) {
		SIMPLE_LOG_INFO(logger) << SLOG_LITERAL("Thread ") << thread_id << SLOG_LITERAL(" logging message ") << i;
		SIMPLE_LOG_WARNING(logger) << SLOG_LITERAL("Test Warning") << i;
		SIMPLE_LOG_ERROR(logger) << SLOG_LITERAL("Test Error") << i;

#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
		SIMPLE_LOG_INFO_FMT(logger, SLOG_LITERAL("fmt log: {}"), i); // c++ 20 ֧��
#endif
	}
	std::cout << std::chrono::system_clock::now() << " @@ logMessagesQueued threadid:" << thread_id << " Done!\n";
}


int main() {
	try {
		CSimpleLogger<false> logger(SLOG_LITERAL("my_log"));
		CQueuedLogger<false> queuedLogger(SLOG_LITERAL("queued_log"));

		const int num_threads = 20;
		const int messages_per_thread = 100000;

		std::cout << "Start test at:" << std::chrono::system_clock::now() << "use " << num_threads << " thread ,each write " << messages_per_thread << " logs" << std::endl;

		std::vector<std::thread> threads;
		for (int i = 0; i < num_threads; ++i) {
			threads.emplace_back(logMessages, std::ref(logger), i, messages_per_thread);
			threads.emplace_back(logMessagesQueued, std::ref(queuedLogger), i, messages_per_thread);
		}

		for (auto& t : threads) {
			t.join();
		}

		std::cout << "Logging complete. Check log.txt for results." << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Logging failed: " << e.what() << std::endl;
	}

	return 0;
}
