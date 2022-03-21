#/**
# * Copyright (c) 2021  Panasonic Corporation.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */

add_executable(rvgpu-renderer
	backend/rvgpu-wayland.c
	backend/rvgpu-gbm.c
	renderer/rvgpu-egl.c
	renderer/rvgpu-input.c
	renderer/rvgpu-offload.c
	cache/rvgpu-renderer-cache.c
	zmq/rvgpu-renderer-zmq.c
	virgl/rvgpu-virgl.c
	ivi/ivi-application-client-protocol.c
	rvgpu-renderer.c
	$<TARGET_OBJECTS:rvgpu-sanity>)
target_include_directories(rvgpu-renderer
	PRIVATE
		${PROJECT_SOURCE_DIR}/include
		${extlibs_INCLUDE_DIRS}
	)
target_compile_definitions(rvgpu-renderer PRIVATE _GNU_SOURCE)
target_link_libraries(rvgpu-renderer
	PRIVATE ${extlibs_LIBRARIES} udev drm zmq pgm pthread)
install(TARGETS rvgpu-renderer RUNTIME DESTINATION bin)
