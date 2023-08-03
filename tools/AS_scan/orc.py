import lib.generics as gen
from lib.result import result
from lib.configuration import configuration
import importlib

import lib.custom_logger as custom_logger

logger = custom_logger.logger


def main(config: configuration, res: result, name: str, resume=False, recursive=False):
    """Main function for the orchestration of the tools to run for the Attack Surface scan


    Ex (in config):

        TOOLS :
            AS_scan:
                brute_subs:
                    activate: True
                    file: "brute_subs.py"
                    wordlist_name: "subdomains.txt"
                    resolver_name: "resolvers.txt"
                    workers: 10
                    recursive: True

    The file need to be inside the tools/AS_scan folder
    All tools script must have a "main" function


    All the others parameters will be passed to the script specificified in the path
    """

    tools = config.config["TOOLS"]["AS_scan"]
    if not resume:
        for tool, tool_config in tools.items():
            file = tool_config.get("file")
            recursive_conf = tool_config.get("recursive")
            if file and recursive and recursive_conf or file and not recursive:
                # Import the tool's script
                module = importlib.import_module(f"tools.AS_scan.{file}")
                # Check if the tool's script has a main function
                if hasattr(module, "main"):
                    # Call the main function of the tool's script
                    try:
                        tool_res = module.main(config=config, res=res, name=name)
                    except Exception as e:
                        logger.error(
                            f"Error: Tool '{tool}' has failed with error : {e}"
                        )
                        continue

                    # Add the tool's result to the main result
                    if tool_res and hasattr(tool_res, "result"):
                        res.result.update(tool_res.result)
                        res.export(name)
                    if not recursive:
                        res.metadata["last_tool"] = tool
                else:
                    logger.error(
                        f"Error: Tool '{tool}' does not have a 'main' function."
                    )
            else:
                logger.error(f"Error: Tool '{tool}' does not have a 'file' parameter.")
    else:
        # resume var contains the name of the tool to resume
        file = tools[resume]["file"]
        module = importlib.import_module(f"tools.{file}")
        tool_res = module.main(config=config, res=res)
        if tool_res and hasattr(tool_res, "result"):
            res.result.update(tool_res.result)
            res.export(name)

            tools_ls = []

            for tool in tools.keys():
                tools_ls.append(tool)

            index = list(tools_ls).index(resume)
            to_use = []
            for i in tools_ls[index + 1 :]:
                to_use.append(i)
            for tool in to_use:
                if recursive and tools[tool]["recursive"] or not recursive:
                    file = tools[tool]["file"]
                    module = importlib.import_module(f"tools.{file}")
                    if hasattr(module, "main"):
                        tool_res = module.main(config=config, res=res, name=name)
                        if tool_res and hasattr(tool_res, "result"):
                            res.result.update(tool_res.result)
                            res.export(name)
                            if not recursive:
                                res.metadata["last_tool"] = tool
