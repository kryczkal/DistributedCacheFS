#define FUSE_USE_VERSION 31

#include "app_constants.hpp"
#include "config/config_loader.hpp"
#include "config/config_types.hpp"
#include "fuse_operations.hpp"

#include <fuse3/fuse.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

int main(int argc, char *argv[])
{
    // Command Line argument parsing
    CLI::App app{std::string(DistributedCacheFS::Constants::APP_NAME)};
    app.allow_extras();

    std::string config_path_str;
    std::string mount_point_str;

    app.add_option("-c,--config", config_path_str, "Path to the configuration JSON file")
        ->required()
        ->check(CLI::ExistingFile);

    app.add_option("mountpoint", mount_point_str, "Path to the FUSE mount point")->required();

    app.set_version_flag(
        "-v,--version", std::string(DistributedCacheFS::Constants::APP_VERSION_STRING)
    );

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    // Initialize default logger (console) before config is parsed
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern(
            std::string(DistributedCacheFS::Constants::DEFAULT_CONSOLE_LOG_PATTERN)
        );
        auto main_logger = std::make_shared<spdlog::logger>(
            std::string(DistributedCacheFS::Constants::APP_NAME), console_sink
        );
        spdlog::set_default_logger(main_logger);
        spdlog::set_level(DistributedCacheFS::Constants::DEFAULT_LOG_LEVEL);
        spdlog::flush_on(DistributedCacheFS::Constants::DEFAULT_FLUSH_LEVEL);
    } catch (const spdlog::spdlog_ex &ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    spdlog::info("{} starting...", DistributedCacheFS::Constants::APP_NAME);

    // Load Configuration
    std::filesystem::path config_path(config_path_str);
    auto config_result = DistributedCacheFS::Config::loadConfigFromFileVerbose(config_path);

    if (!config_result) {
        spdlog::critical("Error loading configuration: {}", config_result.error());
        return EXIT_FAILURE;
    }

    // Setup Core Components
    std::unique_ptr<DistributedCacheFS::Origin::OriginManager> origin_manager;
    std::unique_ptr<DistributedCacheFS::Cache::CacheManager> cache_coordinator;
    try {
        origin_manager =
            std::make_unique<DistributedCacheFS::Origin::OriginManager>(config_result.value().origin
            );
        cache_coordinator = std::make_unique<DistributedCacheFS::Cache::CacheManager>(
            config_result.value(), origin_manager.get()
        );
    } catch (const std::exception &e) {
        spdlog::critical("Error initializing components: {}", e.what());
        return EXIT_FAILURE;
    }

    auto init_res = cache_coordinator->InitializeAll();
    if (!init_res) {
        spdlog::critical("Error initializing cache coordinator: {}", init_res.error().message());
        if (cache_coordinator) {
            auto shutdown_res = cache_coordinator->ShutdownAll();
            if (!shutdown_res) {
                spdlog::error(
                    "Error shutting down cache coordinator: {}", shutdown_res.error().message()
                );
            }
        }
        return EXIT_FAILURE;
    }

    // Initialize Logging Level from Config
    spdlog::set_level(config_result.value().global_settings.log_level);
    spdlog::info(
        "Logging level set to: {}",
        spdlog::level::to_string_view(config_result.value().global_settings.log_level)
    );
    spdlog::info("Mounting {} at {}", mount_point_str, DistributedCacheFS::Constants::APP_NAME);
    spdlog::info("Using Node ID: {}", config_result.value().node_id);

    // Setup Filesystem Context
    auto context_ptr            = std::make_unique<DistributedCacheFS::FileSystemContext>();
    context_ptr->config         = std::move(config_result.value());
    context_ptr->origin_manager = std::move(origin_manager);
    context_ptr->cache_manager  = std::move(cache_coordinator);

    // Construct arguments for fuse_main
    std::vector<char *> fuse_argv;
    fuse_argv.push_back(argv[0]);  // Program name

    std::vector<std::string> remaining_args_storage = app.remaining();
    for (const auto &arg : remaining_args_storage) {
        fuse_argv.push_back(const_cast<char *>(arg.c_str()));
    }
    fuse_argv.push_back(const_cast<char *>(mount_point_str.c_str()));

    spdlog::debug("Arguments passed to fuse_main:");
    for (const char *arg : fuse_argv) {
        if (arg) {
            spdlog::debug("  '{}'", arg);
        }
    }
    // Initialize FUSE Operations
    // Ensure ops struct lives longer than fuse_main
    static fuse_operations fs_ops = DistributedCacheFS::FuseOps::get_fuse_operations();

    // Start FUSE Main Loop
    spdlog::info("Starting FUSE main loop...");
    int fuse_ret =
        fuse_main(static_cast<int>(fuse_argv.size()), fuse_argv.data(), &fs_ops, context_ptr.get());
    spdlog::trace("FUSE main loop finished with code: {}", fuse_ret);

    spdlog::info("Shutting down components and cleaning up resources...");

    if (cache_coordinator) {
        auto shutdown_res = cache_coordinator->ShutdownAll();
        if (!shutdown_res) {
            spdlog::error(
                "Error shutting down cache coordinator: {}", shutdown_res.error().message()
            );
        }
    }

    spdlog::info("{} exiting...", DistributedCacheFS::Constants::APP_NAME);
    spdlog::shutdown();

    return fuse_ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
