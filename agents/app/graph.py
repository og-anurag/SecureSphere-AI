"""
Wires all the agent nodes into a single LangGraph StateGraph.

Flow:
    START -> commander -> (conditional routing) -> one specialist agent -> report_generator -> END

To add a new agent (e.g. an SSL-certificate deep-check), you only need to:
  1. Write a node function (state in -> state out) in app/agents/.
  2. Add it with graph.add_node(...).
  3. Add it as a possible destination in commander's routing map.
  4. Point its edge at "report_generator".
"""
from langgraph.graph import StateGraph, END
from .state import SecurityState
from .agents.commander import commander_node, route_after_commander
from .agents.browser_agent import browser_agent_node
from .agents.email_agent import email_agent_node
from .agents.apk_agent import apk_agent_node
from .agents.payment_agent import payment_agent_node
from .agents.report_agent import report_generator_node
from .agents.qr_agent import qr_agent_node

def build_graph():
    graph = StateGraph(SecurityState)

    graph.add_node("commander", commander_node)
    graph.add_node("browser_agent", browser_agent_node)
    graph.add_node("email_agent", email_agent_node)
    graph.add_node("apk_agent", apk_agent_node)
    graph.add_node("payment_agent", payment_agent_node)
    graph.add_node("report_generator", report_generator_node)
    graph.add_node("qr_agent", qr_agent_node)
    graph.set_entry_point("commander")

    graph.add_conditional_edges(
        "commander",
        route_after_commander,
        {
    "browser_agent": "browser_agent",
    "email_agent": "email_agent",
    "apk_agent": "apk_agent",
    "payment_agent": "payment_agent",
    "qr_agent": "qr_agent",
    "report_generator": "report_generator",
},
    )

    for agent in [
    "browser_agent",
    "email_agent",
    "apk_agent",
    "payment_agent",
    "qr_agent",
]:
        graph.add_edge(agent, "report_generator")

    graph.add_edge("report_generator", END)

    return graph.compile()


# Compiled once, reused across requests
security_graph = build_graph()
