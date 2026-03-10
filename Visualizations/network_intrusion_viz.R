# Network Intrusion Detection Data Visualization - Shiny App
# Author: Abed
# Date: 2025-06-19
# Consolidated single file version
install_if_missing <- function(pkg) {
  if (!require(pkg, character.only = TRUE, quietly = TRUE)) {
    install.packages(pkg, dependencies = TRUE, repos = "https://cloud.r-project.org")
    library(pkg, character.only = TRUE)}}
required_packages <- c("shiny","shinydashboard", "DT","plotly","ggplot2","dplyr","data.table","viridis","RColorBrewer","scales","tidyr","forcats")

cat("Checking and installing required packages...\n")
for (pkg in required_packages) {
  cat(paste("Checking", pkg, "...\n"))
  install_if_missing(pkg)}

if (rstudioapi::isAvailable()) {
  setwd(dirname(rstudioapi::getActiveDocumentContext()$path))}

library(shiny)
library(shinydashboard)
library(DT)
library(plotly)
library(ggplot2)
library(dplyr)
library(data.table)
library(viridis)
library(RColorBrewer)
library(scales)
library(forcats)
library(tidyr)

data <- fread("data.csv")
  colnames(data)[1:42] <- c(
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragt", "urgent", "hot", "num_fail_login", "logged_in",
    "nu_comprom", "root_shell", "su_attempted", "num_root", "nu_file_creat",
    "nu_shells", "nu_access_files", "nu_out_cmd", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_h_rate", "host_count", "host_srv_count", "h_same_sr_rate",
    "h_diff_srv_rate", "h_src_port_rate", "h_srv_d_h_rate", "h_serror_rate",
    "h_sr_serror_rate", "h_rerror_rate", "h_sr_rerror_rate", "class")
  
data$class <- as.factor(data$class)
data$protocol_type <- as.factor(data$protocol_type)
data$service <- as.factor(data$service)
data$flag <- as.factor(data$flag)
  
data <- distinct(data) # Removes duplicate rows from dplyr package

create_protocol_data <- function(data) {# This function processes raw protocol data for the pie chart
  protocol_counts <- table(data$protocol_type)
  known_protocols <- c("b'tcp'", "b'udp'", "b'icmp'")
  protocol_df <- data.frame(
    protocol = character(),
    count = numeric(),
    stringsAsFactors = FALSE)
  for (proto in known_protocols) {
    if (proto %in% names(protocol_counts)) {
      protocol_df <- rbind(protocol_df, 
                          data.frame(protocol = gsub("b'|'", "", proto), 
                                   count = as.numeric(protocol_counts[proto])))}}
  unknown_count <- sum(protocol_counts[!names(protocol_counts) %in% c(known_protocols, "1")])
  if (unknown_count > 0) {
    protocol_df <- rbind(protocol_df, 
                        data.frame(protocol = "Unknown", count = unknown_count))}
  return(protocol_df)}

create_class_protocol_data <- function(data) {
  class_protocol <- data %>%
    group_by(class, protocol_type) %>%
    summarise(count = n(), .groups = 'drop') %>%
    filter(protocol_type %in% c("b'tcp'", "b'udp'", "b'icmp'")) %>%
    mutate(protocol = gsub("b'|'", "", protocol_type))
  
  all_classes <- unique(data$class)
  all_protocols <- c("tcp", "udp", "icmp")
  
  complete_grid <- expand.grid(
    class = all_classes,
    protocol = all_protocols,
    stringsAsFactors = FALSE)
  
  complete_data <- merge(complete_grid, class_protocol, 
                        by = c("class", "protocol"), all.x = TRUE)
  complete_data$count[is.na(complete_data$count)] <- 0  # Merge with actual data, filling missing combinations with 0
  return(complete_data)}

ui <- dashboardPage( # DASHBOARD HEADER - Top navigation bar
  dashboardHeader(title = "Network Intrusion Detection Visualization"),
  dashboardSidebar(  # SIDEBAR - Left navigation menu
    sidebarMenu(
      menuItem("Protocol Distribution", tabName = "protocols", icon = icon("chart-pie")),
      menuItem("Attack Classes", tabName = "classes", icon = icon("chart-bar")),
      menuItem("Feature Analysis", tabName = "features", icon = icon("search")))),
  
  dashboardBody(
    tabItems(
      tabItem(tabName = "protocols",
        fluidRow( # fluidRow creates responsive layout rows
          box(
            title = "Protocol Distribution", status = "primary", solidHeader = TRUE, # primary color theme (blue)
            width = 12, height = "600px",
            plotlyOutput("protocol_pie", height = "550px"))),# Output element for plot
        fluidRow(        # Description box below the chart
          box(
            title = "Chart Description", status = "info", solidHeader = TRUE,
            width = 12,
            p("This pie chart shows the distribution of network traffic across different protocols. The chart is dynamically generated from our dataset. Each slice represents the proportion of traffic for TCP, UDP, ICMP, and Unknown protocols.", style = "font-size: 14px; line-height: 1.6;"),
            p(strong("Key Features:"), style = "font-size: 14px; margin-top: 15px;"),
            tags$ul(
              tags$li("Interactive hover shows exact counts and percentages"),
              tags$li("Colors are automatically assigned using a professional palette"),
              tags$li("Unknown protocols are grouped together for clarity"),
              style = "font-size: 13px; line-height: 1.5;")))),
      # TAB 2: ATTACK CLASSES (BAR CHARTS WITH OPTIONS):
       tabItem(tabName = "classes",
        fluidRow( # Control panel for chart customization
          box(
            title = "Visualization Options", status = "warning", solidHeader = TRUE,
            width = 12,
            checkboxInput("use_log", "Use Log Scale", value = FALSE))),  # CHECKBOX for log scale option
        fluidRow(# Main chart display
          box(title = "Attack Class Distribution by Protocol", status = "primary", solidHeader = TRUE,
            width = 12, height = "700px",
            plotlyOutput("class_bars", height = "650px"))),
        fluidRow( 
          box( # Description panel
            title = "Chart Description", status = "info", solidHeader = TRUE,
            width = 12,
            p("This visualization shows the distribution of different attack classes across network protocols using side-by-side bars for clear comparison of protocol distributions within each attack class.", style = "font-size: 14px; line-height: 1.6;"),
            p(strong("Chart Features:"), style = "font-size: 14px; margin-top: 15px;"),
            tags$ul(
              tags$li("Side-by-side bars allow easy comparison of TCP, UDP, ICMP traffic for each attack class"),
              tags$li("Interactive hover displays exact counts and percentages"),
              tags$li("Log scale option helps visualize classes with very different frequencies"),
              tags$li("All attack classes are displayed, including rare ones"),
              style = "font-size: 13px; line-height: 1.5;")))),
      # TAB 3: FEATURE ANALYSIS (MULTIPLE CHARTS)
      tabItem(tabName = "features",
        fluidRow(# Chart 1: Attack type distribution
          box(
            title = "Attack Type Distribution", status = "primary", solidHeader = TRUE,
            width = 12, height = "500px",
            plotlyOutput("attack_type_chart", height = "450px"))),
        fluidRow(# Chart 2: Hourly patterns with interactive controls
          box(
            title = "Attack Distribution by Hour", status = "warning", solidHeader = TRUE,
            width = 12, height = "600px",
            fluidRow(
              column(12,
                sliderInput("zoom_range", "Zoom to Hour Range:", min = 0, max = 24, value = c(0, 24), step = 1),# SLIDER INPUT for zooming into specific hours
                checkboxInput("show_peak_labels", "Show Peak Labels", value = TRUE))),
            plotlyOutput("hourly_pattern_chart", height = "450px"))),
        fluidRow(
          box(
            title = "Normal vs Attack Traffic Description", status = "info", solidHeader = TRUE,
            width = 6,
            p("This chart categorizes all network connections into Normal Traffic and Attack Traffic, broken down by protocol type. It provides a high-level security overview of our network data.", style = "font-size: 14px; line-height: 1.6;"),
            p(strong("Categories:"), style = "font-size: 14px; margin-top: 10px;"),
            tags$ul(
              tags$li(strong("Normal Traffic:"), "Legitimate network connections"),
              tags$li(strong("Attack Traffic:"), "Malicious or suspicious activities"),
              tags$li(strong("Unclassified:"), "Connections with unknown classification"),
              style = "font-size: 13px; line-height: 1.5;")),
          box(
            title = "Hourly Pattern Description", status = "info", solidHeader = TRUE,
            width = 6,
            p("This time-series chart shows network activity patterns across the full 24-hour cycle (0:00 to 24:00). Hour 0 represents midnight to 1:00, and hour 24 shows the same data as hour 0 to complete the 24-hour visualization cycle.", style = "font-size: 14px; line-height: 1.6;"),
            p(strong("Features:"), style = "font-size: 14px; margin-top: 10px;"),
            tags$ul(
              tags$li("Colored background regions for different time periods"),
              tags$li("Zoom slider to focus on specific hours"),
              tags$li("Peak detection to highlight unusual activity"),
              tags$li("Separate lines for normal and attack traffic patterns"),
              style = "font-size: 13px; line-height: 1.5;")))))))
# SERVER LOGIC SECTION:
server <- function(input, output, session) {
  protocol_data <- reactive({create_protocol_data(data)})
  class_protocol_data <- reactive({
    complete_data <- create_class_protocol_data(data)
    complete_data <- complete_data[complete_data$count > 0, ]
    complete_data})
# OUTPUT 1: PROTOCOL PIE CHART
  output$protocol_pie <- renderPlotly({
    proto_data <- protocol_data()
    
    # Create consistent color mapping to match second plot
    protocol_colors <- c(
      "tcp" = "#3498db",    # Blue
      "udp" = "#2ecc71",    # Green
      "icmp" = "#f39c12",   # Orange
      "Unknown" = "#95a5a6" # Gray for unknown
    )
    
    # Map colors to protocols in the data
    chart_colors <- sapply(proto_data$protocol, function(p) {
      if (p %in% names(protocol_colors)) {
        return(protocol_colors[p])
      } else {
        return("#95a5a6")  # Default gray for any unexpected protocols
      }
    })
    
    p <- plot_ly(proto_data,     # CREATING PIE CHART using plot_ly
                labels = ~protocol, 
                values = ~count,
                type = 'pie',
                textposition = 'inside', # Label position
                textinfo = 'label+percent+value', # What to show in labels
                hovertemplate = '<b>%{label}</b><br>Count: %{value:,}<br>Percentage: %{percent}<extra></extra>',
                marker = list(colors = chart_colors,
                             line = list(color = '#FFFFFF', width = 2))) %>%
      layout(title = list(text = "Network Traffic Distribution by Protocol<br><span style='font-size:12px;'>Dynamically Generated from Dataset</span>",
                         font = list(size = 16)),
             showlegend = TRUE,
             font = list(size = 12),
             margin = list(t = 80, b = 20, l = 20, r = 20)) # MARGIN CONTROL: top, bottom, left, right
    p})
# OUTPUT 2: CLASS DISTRIBUTION BAR CHART:
  output$class_bars <- renderPlotly({
    complete_data <- class_protocol_data()
    p <- ggplot(complete_data, aes(x = class, y = count, fill = protocol)) +
      geom_bar(stat = "identity", 
               position = "dodge", # POSITION: Fixed to side-by-side bars
               alpha = 0.9) +
      scale_fill_manual(values = c("tcp" = "#3498db", "udp" = "#2ecc71", "icmp" = "#f39c12")) + # COLOR ASSIGNMENT: Manual color scale with specific colors for each protocol
      labs(title = "Network Attack Class Distribution by Protocol<br><span style='font-size:12px;'></span>", # TITLE: Fixed title
           x = "Attack Class",
           y = if(input$use_log) "Count (Log Scale)" else "Count", # Y-AXIS LABEL: Conditional
           fill = "Protocol") + #legend title
      theme_minimal() + # THEME CUSTOMIZATION - Axis text, title, legend positioning
      theme(axis.text.x = element_text(angle = 45, hjust = 1, size = 10), # Rotate x-axis label
            plot.title = element_text(size = 14, hjust = 0.5),
            legend.position = "top", # LEGEND POSITION: Top
            plot.margin = margin(t = 30, r = 20, b = 20, l = 20, unit = "pt"))
    # Y-AXIS SCALING: Conditional log scale:
    if (input$use_log) {
      p <- p + scale_y_log10(labels = scales::comma)
    } else {
      p <- p + scale_y_continuous(labels = scales::comma)}
    # CONVERT TO INTERACTIVE PLOT and configure layout
    ggplotly(p, tooltip = c("fill", "x", "y")) %>% # TOOLTIP: Show fill, x, y values
      layout(margin = list(t = 100), legend = list( # LEGEND CONFIGURATION: Horizontal, positioned above chart
          orientation = "h", #horizontal orientation
          y = 1.1,
          x = 0.5,
          xanchor = "center"),
        hovermode = "closest")})
# OUTPUT 3: ATTACK TYPE DISTRIBUTION CHART:
  output$attack_type_chart <- renderPlotly({
    attack_data <- data %>%
      mutate(
        attack_type = case_when(
          grepl("normal", class, ignore.case = TRUE) ~ "Normal Traffic",
          class == "" ~ "Unclassified",
          TRUE ~ "Attack Traffic")) %>%
      count(attack_type, protocol_type) %>%
      filter(protocol_type %in% c("b'tcp'", "b'udp'", "b'icmp'")) %>%
      mutate(protocol = gsub("b'|'", "", protocol_type))
    p <- ggplot(attack_data, aes(x = attack_type, y = n, fill = protocol)) +
      geom_bar(stat = "identity", position = "dodge") +
      scale_fill_manual(values = c("tcp" = "#3498db", "udp" = "#2ecc71", "icmp" = "#f39c12")) +
      scale_y_continuous(labels = scales::comma) +
      labs(
        title = "Normal Traffic vs Attack Traffic by Protocol<br><span style='font-size:12px;'>Distribution of connections by protocol type</span>",
        x = "Traffic Type",
        y = "Count",
        fill = "Protocol") +
      theme_minimal() +
      theme(
        axis.text.x = element_text(angle = 45, hjust = 1),
        plot.title = element_text(size = 14, hjust = 0.5),
        plot.margin = margin(t = 30, r = 20, b = 20, l = 20, unit = "pt"))
    ggplotly(p, tooltip = c("fill", "x", "y")) %>%
      layout(
        margin = list(t = 100),  # Add more margin at top for title and legend
        legend = list(
          orientation = "h",
          y = 1.1,
          x = 0.5,
          xanchor = "center"))})

# OUTPUT 4: HOURLY PATTERN CHART:
  output$hourly_pattern_chart <- renderPlotly({
    hourly_data <- data %>%    # DATA PROCESSING: Creating hourly patterns
      mutate(
        hour_of_day = (duration %% 86400) %/% 3600,# Convert to hour of day (0-23)
        time_period = case_when(
          hour_of_day >= 0 & hour_of_day <= 5 ~ "Night (0-5)",
          hour_of_day >= 6 & hour_of_day <= 11 ~ "Morning (6-11)", 
          hour_of_day >= 12 & hour_of_day <= 17 ~ "Afternoon (12-17)",
          hour_of_day >= 18 & hour_of_day <= 23 ~ "Evening (18-23)"),
        attack_type = case_when(        # TRAFFIC TYPE CLASSIFICATION: Same logic as attack_type_chart
          grepl("normal", class, ignore.case = TRUE) ~ "Normal Traffic",
          class == "" ~ "Unclassified",
          TRUE ~ "Attack Traffic")) %>%
      count(hour_of_day, attack_type) %>% # Count by hour and type
      complete(hour_of_day = 0:23, attack_type, fill = list(n = 0))
    hour_24_data <- hourly_data %>% #duplicating for reflection on the other side
      filter(hour_of_day == 0) %>%
      mutate(hour_of_day = 24)
    hourly_data <- bind_rows(hourly_data, hour_24_data)
    zoomed_data <- hourly_data %>% # ZOOM FILTERING: Filter data based on user slider input
      filter(hour_of_day >= input$zoom_range[1], hour_of_day <= input$zoom_range[2])
    peak_points <- list()        # PEAK DETECTION: Identify peak points for attack and normal traffic
    if(input$show_peak_labels) {
      attack_data <- filter(zoomed_data, attack_type == "Attack Traffic")
      normal_data <- filter(zoomed_data, attack_type == "Normal Traffic")
      attack_peaks <- attack_data %>%# PEAK IDENTIFICATION ALGORITHM: Find local maxima above 50% of global max
        arrange(hour_of_day) %>%
        mutate(is_peak = c(FALSE, diff(n) > 0) & c(diff(n) < 0, FALSE) & n > max(n) * 0.5) %>%
        filter(is_peak | n == max(n)) #including global max
      normal_peaks <- normal_data %>%
        arrange(hour_of_day) %>%
        mutate(is_peak = c(FALSE, diff(n) > 0) & c(diff(n) < 0, FALSE) & n > max(n) * 0.5) %>%
        filter(is_peak | n == max(n))
      # CREATE PEAK ANNOTATIONS
      for(i in 1:nrow(attack_peaks)) {# Attack traffic peaks
        peak_points <- append(peak_points, list(
          list(
            x = attack_peaks$hour_of_day[i],
            y = attack_peaks$n[i],
            text = paste0("Peak: ", format(attack_peaks$n[i], big.mark=",")),
            showarrow = TRUE,
            arrowhead = 2,
            arrowsize = 1,
            arrowwidth = 2,
            arrowcolor = '#e74c3c',# Red color for attack peaks
            ax = 20,
            ay = -40,
            font = list(color = '#e74c3c'))))}
      for(i in 1:nrow(normal_peaks)) {# Normal traffic peaks
        peak_points <- append(peak_points, list(
          list(
            x = normal_peaks$hour_of_day[i],
            y = normal_peaks$n[i],
            text = paste0("Peak: ", format(normal_peaks$n[i], big.mark=",")),
            showarrow = TRUE,
            arrowhead = 2,
            arrowsize = 1,
            arrowwidth = 2,
            arrowcolor = '#2ecc71',
            ax = 20,
            ay = -40,
            font = list(color = '#2ecc71'))))}}
    # CALCULATE Y-AXIS RANGE for background shapes
    max_y_val <- max(zoomed_data$n) * 1.1
    shapes <- list(
      list(type = "rect", fillcolor = "rgba(232,212,248,0.3)", line = list(width = 0),# Night period (0-5) - Purple tint
           x0 = max(input$zoom_range[1], 0) - 0.5, 
           x1 = min(input$zoom_range[2], 5) + 0.5, 
           y0 = 0, y1 = max_y_val, layer = "below"),
      list(type = "rect", fillcolor = "rgba(248,239,212,0.3)", line = list(width = 0),# Morning period (6-11) - Yellow tint
           x0 = max(input$zoom_range[1], 6) - 0.5, 
           x1 = min(input$zoom_range[2], 11) + 0.5, 
           y0 = 0, y1 = max_y_val, layer = "below"),
      list(type = "rect", fillcolor = "rgba(248,225,212,0.3)", line = list(width = 0), # Afternoon period (12-17) - Orange tint
           x0 = max(input$zoom_range[1], 12) - 0.5, 
           x1 = min(input$zoom_range[2], 17) + 0.5, 
           y0 = 0, y1 = max_y_val, layer = "below"),
      list(type = "rect", fillcolor = "rgba(212,229,248,0.3)", line = list(width = 0), # Evening period (18-23) - Blue tint
           x0 = max(input$zoom_range[1], 18) - 0.5, 
           x1 = min(input$zoom_range[2], 24) + 0.5, 
           y0 = 0, y1 = max_y_val, layer = "below"))
    period_labels <- list() # PERIOD LABELS: Adding text labels for time periods
    zoom_range <- input$zoom_range
    if(zoom_range[1] <= 5 && zoom_range[2] >= 0) {
      period_labels <- append(period_labels, list(
        list(x = max(2.5, (max(zoom_range[1], 0) + min(zoom_range[2], 5))/2), 
             y = max_y_val * 0.95, text = "Night", showarrow = FALSE)))}
    if(zoom_range[1] <= 11 && zoom_range[2] >= 6) {
      period_labels <- append(period_labels, list(
        list(x = max(8.5, (max(zoom_range[1], 6) + min(zoom_range[2], 11))/2), 
             y = max_y_val * 0.95, text = "Morning", showarrow = FALSE)))}
    if(zoom_range[1] <= 17 && zoom_range[2] >= 12) {
      period_labels <- append(period_labels, list(
        list(x = max(14.5, (max(zoom_range[1], 12) + min(zoom_range[2], 17))/2), 
             y = max_y_val * 0.95, text = "Afternoon", showarrow = FALSE)))}
    if(zoom_range[1] <= 24 && zoom_range[2] >= 18) {
      period_labels <- append(period_labels, list(
        list(x = max(21, (max(zoom_range[1], 18) + min(zoom_range[2], 24))/2), 
             y = max_y_val * 0.95, text = "Evening", showarrow = FALSE)))}
    
    y_axis <- list( # Y-AXIS CONFIGURATION: Title, type, gridlines
      title = "Number of Connections",
      type = "linear",
      showgrid = TRUE)
      
    p <- plot_ly() %>%
      add_trace(
        data = filter(zoomed_data, attack_type == "Attack Traffic"),
        x = ~hour_of_day,
        y = ~n,
        type = 'scatter',
        mode = 'lines+markers',
        name = 'Attack Traffic',
        line = list(color = '#e74c3c', width = 3),
        marker = list(color = '#e74c3c', size = 8),
        hovertemplate = paste(
          '<b>Hour: %{x}:00</b><br>',
          'Attack Traffic: %{y:,}<br>',
          '<extra></extra>')) %>%
      add_trace(
        data = filter(zoomed_data, attack_type == "Normal Traffic"),
        x = ~hour_of_day,
        y = ~n,
        type = 'scatter',
        mode = 'lines+markers',
        name = 'Normal Traffic',
        line = list(color = '#2ecc71', width = 3),
        marker = list(color = '#2ecc71', size = 8),
        hovertemplate = paste(
          '<b>Hour: %{x}:00</b><br>',
          'Normal Traffic: %{y:,}<br>',
          '<extra></extra>')) %>%
      layout(
        title = list(
          text = paste0("Hourly Pattern of Network Traffic<br><span style='font-size:14px;'>Hours ", 
                      input$zoom_range[1], ":00 to ", input$zoom_range[2], ":00</span>"),
          font = list(size = 16)),
        xaxis = list(
          title = "Hour of Day",
          tickvals = input$zoom_range[1]:input$zoom_range[2],
          ticktext = paste0(input$zoom_range[1]:input$zoom_range[2], ":00"),
          showgrid = TRUE,
          range = c(input$zoom_range[1] - 0.5, input$zoom_range[2] + 0.5),
          automargin = TRUE),
        yaxis = y_axis,
        shapes = shapes,
        annotations = c(period_labels, if(input$show_peak_labels) peak_points else list()),
        legend = list(
          orientation = "h",
          y = 1.1,
          x = 0.5,
          xanchor = "center"),
        margin = list(t = 100, b = 100))
    p})}

cat("Launching Shiny app...\n")
shinyApp(ui = ui, server = server)
