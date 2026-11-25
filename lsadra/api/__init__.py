"""The REST and WebSocket API the dashboard and the desktop app use.

Routers: ``dashboard`` (/api/dashboard/*), ``identity`` (/api/auth/* and
account management), ``models`` (/api/models/*) and ``alert_stream``
(/ws/alerts). ``data_layer`` holds the cached read queries behind them and
``report_generator`` builds the PDF report.
"""
