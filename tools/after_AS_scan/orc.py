import lib.generics as gen
from lib.result import result
import importlib

import lib.custom_logger as custom_logger

logger = custom_logger.logger


def execute_tool(config: gen.configuration, res: result, name: str, tool: str) -> None:
    """
    Executes a single tool specified by the tool parameter.

    :param config: gen.configuration object containing the configuration for the tools
    :param res: result object containing the results of the tools
    :param tool: str containing the name of the tool to execute
    :return: None
    """
    tool_config = config.config["TOOLS"]["after_AS_scan"][tool]
    file = tool_config.get("file")

    if file:
        module = importlib.import_module(f"tools.after_AS_scan.{file}")
        if hasattr(module, "main"):
            try:
                tool_res = module.main(config=config, res=res)
            except Exception as e:
                logger.error(f"Error: Tool '{tool}' has failed with error : {e}")
                return

            if tool_res and hasattr(tool_res, "result"):
                res.result.update(tool_res.result)
                res.export(name)
            res.metadata["last_tool"] = tool
        else:
            logger.error(f"Error: Tool '{tool}' does not have a 'main' function.")
    else:
        logger.error(f"Error: Tool '{tool}' does not have a 'file' parameter.")


def execute_all_tools(
    config: gen.configuration, res: result, name: str, resume: bool = False
) -> None:
    """
    Executes all the tools specified in the configuration.

    :param config: gen.configuration object containing the configuration for the tools
    :param res: result object containing the results of the tools
    :param name: str containing the name of the result file
    :param resume: bool indicating whether to resume the execution of the tools from a specific tool
    :return: None
    """
    tools = config.config["TOOLS"]["after_AS_scan"]
    tools_ls = list(tools.keys())

    if resume:
        index = tools_ls.index(resume)
        tools_ls = tools_ls[index:]

    for tool in tools_ls:
        execute_tool(config, res, name, tool)
        res.export(name)


def main(
    config: gen.configuration, res: result, name: str, resume: bool = False
) -> None:
    """
    Main function for the orchestration of the tools.

    :param config: gen.configuration object containing the configuration for the tools
    :param res: result object containing the results of the tools
    :param name: str containing the name of the result file
    :param resume: bool indicating whether to resume the execution of the tools from a specific tool
    :return: None
    """
    if not resume:
        execute_all_tools(config, res, name)
    else:
        execute_all_tools(config, res, name, resume)
