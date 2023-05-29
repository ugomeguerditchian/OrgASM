import lib.generics as gen
from lib.result import result
import importlib

import lib.custom_logger as custom_logger

logger = custom_logger.logger


def main(config: gen.configuration, res: result, name: str, resume=False):
    """Main function for the orchestration of the tools


    Ex (in config):

        TOOLS :
        ports_scanner:
            file: "ports_scanner.py"
            trough_proxy: False
            detect_service: True
            detect_web_port: True

    The file need to be inside the tools folder
    All tools script must have a "main" function

    generic parameters:
        file : file name of the script

    All the others parameters will be passed to the script specificified in the path

    res will also be passed to the script so you can add your own data architecture to the result
    you can create your own child reslult to implement new def like "add_ports"
    """

    tools = config.config["TOOLS"]
    if not resume:
        for tool, tool_config in tools.items():
            file = tool_config.get("file")

            if file:
                # Import the tool's script
                module = importlib.import_module(f"tools.{file}")
                # Check if the tool's script has a main function
                if hasattr(module, "main"):
                    # Call the main function of the tool's script
                    try:
                        tool_res = module.main(config=config, res=res)
                    except Exception as e:
                        logger.error(
                            f"Error: Tool '{tool}' has failed with error : {e}"
                        )
                        continue

                    # Add the tool's result to the main result
                    if tool_res and hasattr(tool_res, "result"):
                        res.result.update(tool_res.result)
                        res.export(name)
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
                file = tools[tool]["file"]
                module = importlib.import_module(f"tools.{file}")
                tool_res = module.main(config=config, res=res)
                if tool_res and hasattr(tool_res, "result"):
                    res.result.update(tool_res.result)
                    res.export(name)
