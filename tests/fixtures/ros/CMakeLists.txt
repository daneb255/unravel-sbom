cmake_minimum_required(VERSION 3.5)
project(my_ros2_pkg)

set(MY_ROS2_DEPS
  ament_index_cpp
  builtin_interfaces
  diagnostic_msgs
  lifecycle_msgs
  nav_msgs
  rclcpp
  rclcpp_components
  sensor_msgs
  std_msgs
  tf2_ros
)

# find individual packages
find_package(my_camera_lib REQUIRED CONFIG)
find_package(ament_cmake_auto REQUIRED)
find_package(ament_cmake_ros REQUIRED)

# ROS2 ament bulk dependency finder — expands ${MY_ROS2_DEPS}
ament_auto_find_build_dependencies(REQUIRED ${MY_ROS2_DEPS})

add_library(my_ros2_camera_node SHARED src/lib/camera_node.cpp)
ament_target_dependencies(my_ros2_camera_node ${MY_ROS2_DEPS})

if(BUILD_TESTING)
  find_package(launch_testing_ament_cmake)
endif()

ament_auto_package()
