/**
 * @fileoverview gRPC-Web generated client stub for 
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck



const grpc = {};
grpc.web = require('grpc-web');


var google_protobuf_empty_pb = require('google-protobuf/google/protobuf/empty_pb.js')

var google_protobuf_timestamp_pb = require('google-protobuf/google/protobuf/timestamp_pb.js')
const proto = require('./safescale_pb.js');

/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.TenantServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.TenantServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TenantCleanupRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_TenantService_Cleanup = new grpc.web.MethodDescriptor(
  '/TenantService/Cleanup',
  grpc.web.MethodType.UNARY,
  proto.TenantCleanupRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.TenantCleanupRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.TenantCleanupRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.cleanup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Cleanup',
      request,
      metadata || {},
      methodDescriptor_TenantService_Cleanup,
      callback);
};


/**
 * @param {!proto.TenantCleanupRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.cleanup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Cleanup',
      request,
      metadata || {},
      methodDescriptor_TenantService_Cleanup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.google.protobuf.Empty,
 *   !proto.TenantName>}
 */
const methodDescriptor_TenantService_Get = new grpc.web.MethodDescriptor(
  '/TenantService/Get',
  grpc.web.MethodType.UNARY,
  google_protobuf_empty_pb.Empty,
  proto.TenantName,
  /**
   * @param {!proto.google.protobuf.Empty} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TenantName.deserializeBinary
);


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TenantName)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TenantName>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.get =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Get',
      request,
      metadata || {},
      methodDescriptor_TenantService_Get,
      callback);
};


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TenantName>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.get =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Get',
      request,
      metadata || {},
      methodDescriptor_TenantService_Get);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TenantName,
 *   !proto.TenantInspectResponse>}
 */
const methodDescriptor_TenantService_Inspect = new grpc.web.MethodDescriptor(
  '/TenantService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.TenantName,
  proto.TenantInspectResponse,
  /**
   * @param {!proto.TenantName} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TenantInspectResponse.deserializeBinary
);


/**
 * @param {!proto.TenantName} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TenantInspectResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TenantInspectResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Inspect',
      request,
      metadata || {},
      methodDescriptor_TenantService_Inspect,
      callback);
};


/**
 * @param {!proto.TenantName} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TenantInspectResponse>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Inspect',
      request,
      metadata || {},
      methodDescriptor_TenantService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.google.protobuf.Empty,
 *   !proto.TenantList>}
 */
const methodDescriptor_TenantService_List = new grpc.web.MethodDescriptor(
  '/TenantService/List',
  grpc.web.MethodType.UNARY,
  google_protobuf_empty_pb.Empty,
  proto.TenantList,
  /**
   * @param {!proto.google.protobuf.Empty} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TenantList.deserializeBinary
);


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TenantList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TenantList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/List',
      request,
      metadata || {},
      methodDescriptor_TenantService_List,
      callback);
};


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TenantList>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/List',
      request,
      metadata || {},
      methodDescriptor_TenantService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TenantScanRequest,
 *   !proto.ScanResultList>}
 */
const methodDescriptor_TenantService_Scan = new grpc.web.MethodDescriptor(
  '/TenantService/Scan',
  grpc.web.MethodType.UNARY,
  proto.TenantScanRequest,
  proto.ScanResultList,
  /**
   * @param {!proto.TenantScanRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ScanResultList.deserializeBinary
);


/**
 * @param {!proto.TenantScanRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ScanResultList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ScanResultList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.scan =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Scan',
      request,
      metadata || {},
      methodDescriptor_TenantService_Scan,
      callback);
};


/**
 * @param {!proto.TenantScanRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ScanResultList>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.scan =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Scan',
      request,
      metadata || {},
      methodDescriptor_TenantService_Scan);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TenantName,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_TenantService_Set = new grpc.web.MethodDescriptor(
  '/TenantService/Set',
  grpc.web.MethodType.UNARY,
  proto.TenantName,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.TenantName} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.TenantName} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.set =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Set',
      request,
      metadata || {},
      methodDescriptor_TenantService_Set,
      callback);
};


/**
 * @param {!proto.TenantName} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.set =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Set',
      request,
      metadata || {},
      methodDescriptor_TenantService_Set);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TenantUpgradeRequest,
 *   !proto.TenantUpgradeResponse>}
 */
const methodDescriptor_TenantService_Upgrade = new grpc.web.MethodDescriptor(
  '/TenantService/Upgrade',
  grpc.web.MethodType.UNARY,
  proto.TenantUpgradeRequest,
  proto.TenantUpgradeResponse,
  /**
   * @param {!proto.TenantUpgradeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TenantUpgradeResponse.deserializeBinary
);


/**
 * @param {!proto.TenantUpgradeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TenantUpgradeResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TenantUpgradeResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TenantServiceClient.prototype.upgrade =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TenantService/Upgrade',
      request,
      metadata || {},
      methodDescriptor_TenantService_Upgrade,
      callback);
};


/**
 * @param {!proto.TenantUpgradeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TenantUpgradeResponse>}
 *     Promise that resolves to the response
 */
proto.TenantServicePromiseClient.prototype.upgrade =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TenantService/Upgrade',
      request,
      metadata || {},
      methodDescriptor_TenantService_Upgrade);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ImageServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ImageServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ImageListRequest,
 *   !proto.ImageList>}
 */
const methodDescriptor_ImageService_List = new grpc.web.MethodDescriptor(
  '/ImageService/List',
  grpc.web.MethodType.UNARY,
  proto.ImageListRequest,
  proto.ImageList,
  /**
   * @param {!proto.ImageListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ImageList.deserializeBinary
);


/**
 * @param {!proto.ImageListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ImageList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ImageList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ImageServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ImageService/List',
      request,
      metadata || {},
      methodDescriptor_ImageService_List,
      callback);
};


/**
 * @param {!proto.ImageListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ImageList>}
 *     Promise that resolves to the response
 */
proto.ImageServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ImageService/List',
      request,
      metadata || {},
      methodDescriptor_ImageService_List);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.NetworkServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.NetworkServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.NetworkCreateRequest,
 *   !proto.Network>}
 */
const methodDescriptor_NetworkService_Create = new grpc.web.MethodDescriptor(
  '/NetworkService/Create',
  grpc.web.MethodType.UNARY,
  proto.NetworkCreateRequest,
  proto.Network,
  /**
   * @param {!proto.NetworkCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Network.deserializeBinary
);


/**
 * @param {!proto.NetworkCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Network)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Network>|undefined}
 *     The XHR Node Readable Stream
 */
proto.NetworkServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/NetworkService/Create',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Create,
      callback);
};


/**
 * @param {!proto.NetworkCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Network>}
 *     Promise that resolves to the response
 */
proto.NetworkServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/NetworkService/Create',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.NetworkListRequest,
 *   !proto.NetworkList>}
 */
const methodDescriptor_NetworkService_List = new grpc.web.MethodDescriptor(
  '/NetworkService/List',
  grpc.web.MethodType.UNARY,
  proto.NetworkListRequest,
  proto.NetworkList,
  /**
   * @param {!proto.NetworkListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.NetworkList.deserializeBinary
);


/**
 * @param {!proto.NetworkListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.NetworkList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.NetworkList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.NetworkServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/NetworkService/List',
      request,
      metadata || {},
      methodDescriptor_NetworkService_List,
      callback);
};


/**
 * @param {!proto.NetworkListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.NetworkList>}
 *     Promise that resolves to the response
 */
proto.NetworkServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/NetworkService/List',
      request,
      metadata || {},
      methodDescriptor_NetworkService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.Network>}
 */
const methodDescriptor_NetworkService_Inspect = new grpc.web.MethodDescriptor(
  '/NetworkService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.Network,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Network.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Network)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Network>|undefined}
 *     The XHR Node Readable Stream
 */
proto.NetworkServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/NetworkService/Inspect',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Network>}
 *     Promise that resolves to the response
 */
proto.NetworkServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/NetworkService/Inspect',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.NetworkDeleteRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_NetworkService_Delete = new grpc.web.MethodDescriptor(
  '/NetworkService/Delete',
  grpc.web.MethodType.UNARY,
  proto.NetworkDeleteRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.NetworkDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.NetworkDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.NetworkServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/NetworkService/Delete',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Delete,
      callback);
};


/**
 * @param {!proto.NetworkDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.NetworkServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/NetworkService/Delete',
      request,
      metadata || {},
      methodDescriptor_NetworkService_Delete);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SubnetServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SubnetServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SubnetCreateRequest,
 *   !proto.Subnet>}
 */
const methodDescriptor_SubnetService_Create = new grpc.web.MethodDescriptor(
  '/SubnetService/Create',
  grpc.web.MethodType.UNARY,
  proto.SubnetCreateRequest,
  proto.Subnet,
  /**
   * @param {!proto.SubnetCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Subnet.deserializeBinary
);


/**
 * @param {!proto.SubnetCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Subnet)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Subnet>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/Create',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Create,
      callback);
};


/**
 * @param {!proto.SubnetCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Subnet>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/Create',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SubnetListRequest,
 *   !proto.SubnetList>}
 */
const methodDescriptor_SubnetService_List = new grpc.web.MethodDescriptor(
  '/SubnetService/List',
  grpc.web.MethodType.UNARY,
  proto.SubnetListRequest,
  proto.SubnetList,
  /**
   * @param {!proto.SubnetListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SubnetList.deserializeBinary
);


/**
 * @param {!proto.SubnetListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SubnetList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SubnetList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/List',
      request,
      metadata || {},
      methodDescriptor_SubnetService_List,
      callback);
};


/**
 * @param {!proto.SubnetListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SubnetList>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/List',
      request,
      metadata || {},
      methodDescriptor_SubnetService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SubnetInspectRequest,
 *   !proto.Subnet>}
 */
const methodDescriptor_SubnetService_Inspect = new grpc.web.MethodDescriptor(
  '/SubnetService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.SubnetInspectRequest,
  proto.Subnet,
  /**
   * @param {!proto.SubnetInspectRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Subnet.deserializeBinary
);


/**
 * @param {!proto.SubnetInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Subnet)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Subnet>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/Inspect',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Inspect,
      callback);
};


/**
 * @param {!proto.SubnetInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Subnet>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/Inspect',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SubnetDeleteRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SubnetService_Delete = new grpc.web.MethodDescriptor(
  '/SubnetService/Delete',
  grpc.web.MethodType.UNARY,
  proto.SubnetDeleteRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SubnetDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SubnetDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/Delete',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Delete,
      callback);
};


/**
 * @param {!proto.SubnetDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/Delete',
      request,
      metadata || {},
      methodDescriptor_SubnetService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupSubnetBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SubnetService_BindSecurityGroup = new grpc.web.MethodDescriptor(
  '/SubnetService/BindSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupSubnetBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupSubnetBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.bindSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/BindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_BindSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.bindSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/BindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_BindSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupSubnetBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SubnetService_UnbindSecurityGroup = new grpc.web.MethodDescriptor(
  '/SubnetService/UnbindSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupSubnetBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupSubnetBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.unbindSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/UnbindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_UnbindSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.unbindSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/UnbindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_UnbindSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupSubnetBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SubnetService_EnableSecurityGroup = new grpc.web.MethodDescriptor(
  '/SubnetService/EnableSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupSubnetBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupSubnetBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.enableSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/EnableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_EnableSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.enableSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/EnableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_EnableSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupSubnetBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SubnetService_DisableSecurityGroup = new grpc.web.MethodDescriptor(
  '/SubnetService/DisableSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupSubnetBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupSubnetBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.disableSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/DisableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_DisableSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.disableSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/DisableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_SubnetService_DisableSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupSubnetBindRequest,
 *   !proto.SecurityGroupBondsResponse>}
 */
const methodDescriptor_SubnetService_ListSecurityGroups = new grpc.web.MethodDescriptor(
  '/SubnetService/ListSecurityGroups',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupSubnetBindRequest,
  proto.SecurityGroupBondsResponse,
  /**
   * @param {!proto.SecurityGroupSubnetBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupBondsResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupBondsResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupBondsResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SubnetServiceClient.prototype.listSecurityGroups =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SubnetService/ListSecurityGroups',
      request,
      metadata || {},
      methodDescriptor_SubnetService_ListSecurityGroups,
      callback);
};


/**
 * @param {!proto.SecurityGroupSubnetBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupBondsResponse>}
 *     Promise that resolves to the response
 */
proto.SubnetServicePromiseClient.prototype.listSecurityGroups =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SubnetService/ListSecurityGroups',
      request,
      metadata || {},
      methodDescriptor_SubnetService_ListSecurityGroups);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.HostServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.HostServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.HostDefinition,
 *   !proto.Host>}
 */
const methodDescriptor_HostService_Create = new grpc.web.MethodDescriptor(
  '/HostService/Create',
  grpc.web.MethodType.UNARY,
  proto.HostDefinition,
  proto.Host,
  /**
   * @param {!proto.HostDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.HostDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Create',
      request,
      metadata || {},
      methodDescriptor_HostService_Create,
      callback);
};


/**
 * @param {!proto.HostDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Create',
      request,
      metadata || {},
      methodDescriptor_HostService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.Host>}
 */
const methodDescriptor_HostService_Inspect = new grpc.web.MethodDescriptor(
  '/HostService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.Host,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Inspect',
      request,
      metadata || {},
      methodDescriptor_HostService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Inspect',
      request,
      metadata || {},
      methodDescriptor_HostService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.HostStatus>}
 */
const methodDescriptor_HostService_Status = new grpc.web.MethodDescriptor(
  '/HostService/Status',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.HostStatus,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostStatus.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostStatus)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostStatus>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.status =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Status',
      request,
      metadata || {},
      methodDescriptor_HostService_Status,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostStatus>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.status =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Status',
      request,
      metadata || {},
      methodDescriptor_HostService_Status);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.HostListRequest,
 *   !proto.HostList>}
 */
const methodDescriptor_HostService_List = new grpc.web.MethodDescriptor(
  '/HostService/List',
  grpc.web.MethodType.UNARY,
  proto.HostListRequest,
  proto.HostList,
  /**
   * @param {!proto.HostListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostList.deserializeBinary
);


/**
 * @param {!proto.HostListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/List',
      request,
      metadata || {},
      methodDescriptor_HostService_List,
      callback);
};


/**
 * @param {!proto.HostListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostList>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/List',
      request,
      metadata || {},
      methodDescriptor_HostService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_Delete = new grpc.web.MethodDescriptor(
  '/HostService/Delete',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Delete',
      request,
      metadata || {},
      methodDescriptor_HostService_Delete,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Delete',
      request,
      metadata || {},
      methodDescriptor_HostService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_Start = new grpc.web.MethodDescriptor(
  '/HostService/Start',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.start =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Start',
      request,
      metadata || {},
      methodDescriptor_HostService_Start,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.start =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Start',
      request,
      metadata || {},
      methodDescriptor_HostService_Start);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_Stop = new grpc.web.MethodDescriptor(
  '/HostService/Stop',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.stop =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Stop',
      request,
      metadata || {},
      methodDescriptor_HostService_Stop,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.stop =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Stop',
      request,
      metadata || {},
      methodDescriptor_HostService_Stop);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_Reboot = new grpc.web.MethodDescriptor(
  '/HostService/Reboot',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.reboot =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Reboot',
      request,
      metadata || {},
      methodDescriptor_HostService_Reboot,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.reboot =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Reboot',
      request,
      metadata || {},
      methodDescriptor_HostService_Reboot);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.HostDefinition,
 *   !proto.Host>}
 */
const methodDescriptor_HostService_Resize = new grpc.web.MethodDescriptor(
  '/HostService/Resize',
  grpc.web.MethodType.UNARY,
  proto.HostDefinition,
  proto.Host,
  /**
   * @param {!proto.HostDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.HostDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.resize =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/Resize',
      request,
      metadata || {},
      methodDescriptor_HostService_Resize,
      callback);
};


/**
 * @param {!proto.HostDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.resize =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/Resize',
      request,
      metadata || {},
      methodDescriptor_HostService_Resize);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.SshConfig>}
 */
const methodDescriptor_HostService_SSH = new grpc.web.MethodDescriptor(
  '/HostService/SSH',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.SshConfig,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SshConfig.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SshConfig)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SshConfig>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.sSH =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/SSH',
      request,
      metadata || {},
      methodDescriptor_HostService_SSH,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SshConfig>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.sSH =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/SSH',
      request,
      metadata || {},
      methodDescriptor_HostService_SSH);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupHostBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_BindSecurityGroup = new grpc.web.MethodDescriptor(
  '/HostService/BindSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupHostBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupHostBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.bindSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/BindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_BindSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.bindSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/BindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_BindSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupHostBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_UnbindSecurityGroup = new grpc.web.MethodDescriptor(
  '/HostService/UnbindSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupHostBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupHostBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.unbindSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/UnbindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.unbindSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/UnbindSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupHostBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_EnableSecurityGroup = new grpc.web.MethodDescriptor(
  '/HostService/EnableSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupHostBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupHostBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.enableSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/EnableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_EnableSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.enableSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/EnableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_EnableSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupHostBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_DisableSecurityGroup = new grpc.web.MethodDescriptor(
  '/HostService/DisableSecurityGroup',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupHostBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupHostBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.disableSecurityGroup =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/DisableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_DisableSecurityGroup,
      callback);
};


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.disableSecurityGroup =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/DisableSecurityGroup',
      request,
      metadata || {},
      methodDescriptor_HostService_DisableSecurityGroup);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupHostBindRequest,
 *   !proto.SecurityGroupBondsResponse>}
 */
const methodDescriptor_HostService_ListSecurityGroups = new grpc.web.MethodDescriptor(
  '/HostService/ListSecurityGroups',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupHostBindRequest,
  proto.SecurityGroupBondsResponse,
  /**
   * @param {!proto.SecurityGroupHostBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupBondsResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupBondsResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupBondsResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.listSecurityGroups =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/ListSecurityGroups',
      request,
      metadata || {},
      methodDescriptor_HostService_ListSecurityGroups,
      callback);
};


/**
 * @param {!proto.SecurityGroupHostBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupBondsResponse>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.listSecurityGroups =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/ListSecurityGroups',
      request,
      metadata || {},
      methodDescriptor_HostService_ListSecurityGroups);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelBoundsRequest,
 *   !proto.LabelListResponse>}
 */
const methodDescriptor_HostService_ListLabels = new grpc.web.MethodDescriptor(
  '/HostService/ListLabels',
  grpc.web.MethodType.UNARY,
  proto.LabelBoundsRequest,
  proto.LabelListResponse,
  /**
   * @param {!proto.LabelBoundsRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.LabelListResponse.deserializeBinary
);


/**
 * @param {!proto.LabelBoundsRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.LabelListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.LabelListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.listLabels =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/ListLabels',
      request,
      metadata || {},
      methodDescriptor_HostService_ListLabels,
      callback);
};


/**
 * @param {!proto.LabelBoundsRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.LabelListResponse>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.listLabels =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/ListLabels',
      request,
      metadata || {},
      methodDescriptor_HostService_ListLabels);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.HostLabelRequest,
 *   !proto.HostLabelResponse>}
 */
const methodDescriptor_HostService_InspectLabel = new grpc.web.MethodDescriptor(
  '/HostService/InspectLabel',
  grpc.web.MethodType.UNARY,
  proto.HostLabelRequest,
  proto.HostLabelResponse,
  /**
   * @param {!proto.HostLabelRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostLabelResponse.deserializeBinary
);


/**
 * @param {!proto.HostLabelRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostLabelResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostLabelResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.inspectLabel =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/InspectLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_InspectLabel,
      callback);
};


/**
 * @param {!proto.HostLabelRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostLabelResponse>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.inspectLabel =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/InspectLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_InspectLabel);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_BindLabel = new grpc.web.MethodDescriptor(
  '/HostService/BindLabel',
  grpc.web.MethodType.UNARY,
  proto.LabelBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.LabelBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.bindLabel =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/BindLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_BindLabel,
      callback);
};


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.bindLabel =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/BindLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_BindLabel);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_UnbindLabel = new grpc.web.MethodDescriptor(
  '/HostService/UnbindLabel',
  grpc.web.MethodType.UNARY,
  proto.LabelBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.LabelBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.unbindLabel =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/UnbindLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindLabel,
      callback);
};


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.unbindLabel =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/UnbindLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindLabel);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_UpdateLabel = new grpc.web.MethodDescriptor(
  '/HostService/UpdateLabel',
  grpc.web.MethodType.UNARY,
  proto.LabelBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.LabelBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.updateLabel =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/UpdateLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_UpdateLabel,
      callback);
};


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.updateLabel =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/UpdateLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_UpdateLabel);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_ResetLabel = new grpc.web.MethodDescriptor(
  '/HostService/ResetLabel',
  grpc.web.MethodType.UNARY,
  proto.LabelBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.LabelBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.resetLabel =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/ResetLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_ResetLabel,
      callback);
};


/**
 * @param {!proto.LabelBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.resetLabel =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/ResetLabel',
      request,
      metadata || {},
      methodDescriptor_HostService_ResetLabel);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.PublicIPBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_BindPublicIP = new grpc.web.MethodDescriptor(
  '/HostService/BindPublicIP',
  grpc.web.MethodType.UNARY,
  proto.PublicIPBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.PublicIPBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.PublicIPBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.bindPublicIP =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/BindPublicIP',
      request,
      metadata || {},
      methodDescriptor_HostService_BindPublicIP,
      callback);
};


/**
 * @param {!proto.PublicIPBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.bindPublicIP =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/BindPublicIP',
      request,
      metadata || {},
      methodDescriptor_HostService_BindPublicIP);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.PublicIPBindRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_HostService_UnbindPublicIP = new grpc.web.MethodDescriptor(
  '/HostService/UnbindPublicIP',
  grpc.web.MethodType.UNARY,
  proto.PublicIPBindRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.PublicIPBindRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.PublicIPBindRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.HostServiceClient.prototype.unbindPublicIP =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/HostService/UnbindPublicIP',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindPublicIP,
      callback);
};


/**
 * @param {!proto.PublicIPBindRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.HostServicePromiseClient.prototype.unbindPublicIP =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/HostService/UnbindPublicIP',
      request,
      metadata || {},
      methodDescriptor_HostService_UnbindPublicIP);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.TemplateServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.TemplateServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TemplateListRequest,
 *   !proto.TemplateList>}
 */
const methodDescriptor_TemplateService_List = new grpc.web.MethodDescriptor(
  '/TemplateService/List',
  grpc.web.MethodType.UNARY,
  proto.TemplateListRequest,
  proto.TemplateList,
  /**
   * @param {!proto.TemplateListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TemplateList.deserializeBinary
);


/**
 * @param {!proto.TemplateListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TemplateList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TemplateList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TemplateServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TemplateService/List',
      request,
      metadata || {},
      methodDescriptor_TemplateService_List,
      callback);
};


/**
 * @param {!proto.TemplateListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TemplateList>}
 *     Promise that resolves to the response
 */
proto.TemplateServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TemplateService/List',
      request,
      metadata || {},
      methodDescriptor_TemplateService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TemplateMatchRequest,
 *   !proto.TemplateList>}
 */
const methodDescriptor_TemplateService_Match = new grpc.web.MethodDescriptor(
  '/TemplateService/Match',
  grpc.web.MethodType.UNARY,
  proto.TemplateMatchRequest,
  proto.TemplateList,
  /**
   * @param {!proto.TemplateMatchRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.TemplateList.deserializeBinary
);


/**
 * @param {!proto.TemplateMatchRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.TemplateList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.TemplateList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TemplateServiceClient.prototype.match =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TemplateService/Match',
      request,
      metadata || {},
      methodDescriptor_TemplateService_Match,
      callback);
};


/**
 * @param {!proto.TemplateMatchRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.TemplateList>}
 *     Promise that resolves to the response
 */
proto.TemplateServicePromiseClient.prototype.match =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TemplateService/Match',
      request,
      metadata || {},
      methodDescriptor_TemplateService_Match);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.TemplateInspectRequest,
 *   !proto.HostTemplate>}
 */
const methodDescriptor_TemplateService_Inspect = new grpc.web.MethodDescriptor(
  '/TemplateService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.TemplateInspectRequest,
  proto.HostTemplate,
  /**
   * @param {!proto.TemplateInspectRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostTemplate.deserializeBinary
);


/**
 * @param {!proto.TemplateInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostTemplate)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostTemplate>|undefined}
 *     The XHR Node Readable Stream
 */
proto.TemplateServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/TemplateService/Inspect',
      request,
      metadata || {},
      methodDescriptor_TemplateService_Inspect,
      callback);
};


/**
 * @param {!proto.TemplateInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostTemplate>}
 *     Promise that resolves to the response
 */
proto.TemplateServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/TemplateService/Inspect',
      request,
      metadata || {},
      methodDescriptor_TemplateService_Inspect);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.VolumeServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.VolumeServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.VolumeCreateRequest,
 *   !proto.VolumeInspectResponse>}
 */
const methodDescriptor_VolumeService_Create = new grpc.web.MethodDescriptor(
  '/VolumeService/Create',
  grpc.web.MethodType.UNARY,
  proto.VolumeCreateRequest,
  proto.VolumeInspectResponse,
  /**
   * @param {!proto.VolumeCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.VolumeInspectResponse.deserializeBinary
);


/**
 * @param {!proto.VolumeCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.VolumeInspectResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.VolumeInspectResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/Create',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Create,
      callback);
};


/**
 * @param {!proto.VolumeCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.VolumeInspectResponse>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/Create',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.VolumeAttachmentRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_VolumeService_Attach = new grpc.web.MethodDescriptor(
  '/VolumeService/Attach',
  grpc.web.MethodType.UNARY,
  proto.VolumeAttachmentRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.VolumeAttachmentRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.VolumeAttachmentRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.attach =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/Attach',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Attach,
      callback);
};


/**
 * @param {!proto.VolumeAttachmentRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.attach =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/Attach',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Attach);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.VolumeDetachmentRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_VolumeService_Detach = new grpc.web.MethodDescriptor(
  '/VolumeService/Detach',
  grpc.web.MethodType.UNARY,
  proto.VolumeDetachmentRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.VolumeDetachmentRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.VolumeDetachmentRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.detach =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/Detach',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Detach,
      callback);
};


/**
 * @param {!proto.VolumeDetachmentRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.detach =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/Detach',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Detach);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_VolumeService_Delete = new grpc.web.MethodDescriptor(
  '/VolumeService/Delete',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/Delete',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Delete,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/Delete',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.VolumeListRequest,
 *   !proto.VolumeListResponse>}
 */
const methodDescriptor_VolumeService_List = new grpc.web.MethodDescriptor(
  '/VolumeService/List',
  grpc.web.MethodType.UNARY,
  proto.VolumeListRequest,
  proto.VolumeListResponse,
  /**
   * @param {!proto.VolumeListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.VolumeListResponse.deserializeBinary
);


/**
 * @param {!proto.VolumeListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.VolumeListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.VolumeListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/List',
      request,
      metadata || {},
      methodDescriptor_VolumeService_List,
      callback);
};


/**
 * @param {!proto.VolumeListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.VolumeListResponse>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/List',
      request,
      metadata || {},
      methodDescriptor_VolumeService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.VolumeInspectResponse>}
 */
const methodDescriptor_VolumeService_Inspect = new grpc.web.MethodDescriptor(
  '/VolumeService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.VolumeInspectResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.VolumeInspectResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.VolumeInspectResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.VolumeInspectResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.VolumeServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/VolumeService/Inspect',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.VolumeInspectResponse>}
 *     Promise that resolves to the response
 */
proto.VolumeServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/VolumeService/Inspect',
      request,
      metadata || {},
      methodDescriptor_VolumeService_Inspect);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.BucketServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.BucketServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_BucketService_Create = new grpc.web.MethodDescriptor(
  '/BucketService/Create',
  grpc.web.MethodType.UNARY,
  proto.BucketRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.BucketRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Create',
      request,
      metadata || {},
      methodDescriptor_BucketService_Create,
      callback);
};


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Create',
      request,
      metadata || {},
      methodDescriptor_BucketService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketMountRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_BucketService_Mount = new grpc.web.MethodDescriptor(
  '/BucketService/Mount',
  grpc.web.MethodType.UNARY,
  proto.BucketMountRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.BucketMountRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.BucketMountRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.mount =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Mount',
      request,
      metadata || {},
      methodDescriptor_BucketService_Mount,
      callback);
};


/**
 * @param {!proto.BucketMountRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.mount =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Mount',
      request,
      metadata || {},
      methodDescriptor_BucketService_Mount);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketMountRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_BucketService_Unmount = new grpc.web.MethodDescriptor(
  '/BucketService/Unmount',
  grpc.web.MethodType.UNARY,
  proto.BucketMountRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.BucketMountRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.BucketMountRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.unmount =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Unmount',
      request,
      metadata || {},
      methodDescriptor_BucketService_Unmount,
      callback);
};


/**
 * @param {!proto.BucketMountRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.unmount =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Unmount',
      request,
      metadata || {},
      methodDescriptor_BucketService_Unmount);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_BucketService_Delete = new grpc.web.MethodDescriptor(
  '/BucketService/Delete',
  grpc.web.MethodType.UNARY,
  proto.BucketRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.BucketRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Delete',
      request,
      metadata || {},
      methodDescriptor_BucketService_Delete,
      callback);
};


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Delete',
      request,
      metadata || {},
      methodDescriptor_BucketService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketListRequest,
 *   !proto.BucketListResponse>}
 */
const methodDescriptor_BucketService_List = new grpc.web.MethodDescriptor(
  '/BucketService/List',
  grpc.web.MethodType.UNARY,
  proto.BucketListRequest,
  proto.BucketListResponse,
  /**
   * @param {!proto.BucketListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.BucketListResponse.deserializeBinary
);


/**
 * @param {!proto.BucketListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.BucketListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.BucketListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/List',
      request,
      metadata || {},
      methodDescriptor_BucketService_List,
      callback);
};


/**
 * @param {!proto.BucketListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.BucketListResponse>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/List',
      request,
      metadata || {},
      methodDescriptor_BucketService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketRequest,
 *   !proto.BucketResponse>}
 */
const methodDescriptor_BucketService_Inspect = new grpc.web.MethodDescriptor(
  '/BucketService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.BucketRequest,
  proto.BucketResponse,
  /**
   * @param {!proto.BucketRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.BucketResponse.deserializeBinary
);


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.BucketResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.BucketResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Inspect',
      request,
      metadata || {},
      methodDescriptor_BucketService_Inspect,
      callback);
};


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.BucketResponse>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Inspect',
      request,
      metadata || {},
      methodDescriptor_BucketService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.BucketRequest,
 *   !proto.BucketDownloadResponse>}
 */
const methodDescriptor_BucketService_Download = new grpc.web.MethodDescriptor(
  '/BucketService/Download',
  grpc.web.MethodType.UNARY,
  proto.BucketRequest,
  proto.BucketDownloadResponse,
  /**
   * @param {!proto.BucketRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.BucketDownloadResponse.deserializeBinary
);


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.BucketDownloadResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.BucketDownloadResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.BucketServiceClient.prototype.download =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/BucketService/Download',
      request,
      metadata || {},
      methodDescriptor_BucketService_Download,
      callback);
};


/**
 * @param {!proto.BucketRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.BucketDownloadResponse>}
 *     Promise that resolves to the response
 */
proto.BucketServicePromiseClient.prototype.download =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/BucketService/Download',
      request,
      metadata || {},
      methodDescriptor_BucketService_Download);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SshServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SshServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SshCommand,
 *   !proto.SshResponse>}
 */
const methodDescriptor_SshService_Run = new grpc.web.MethodDescriptor(
  '/SshService/Run',
  grpc.web.MethodType.UNARY,
  proto.SshCommand,
  proto.SshResponse,
  /**
   * @param {!proto.SshCommand} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SshResponse.deserializeBinary
);


/**
 * @param {!proto.SshCommand} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SshResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SshResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SshServiceClient.prototype.run =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SshService/Run',
      request,
      metadata || {},
      methodDescriptor_SshService_Run,
      callback);
};


/**
 * @param {!proto.SshCommand} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SshResponse>}
 *     Promise that resolves to the response
 */
proto.SshServicePromiseClient.prototype.run =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SshService/Run',
      request,
      metadata || {},
      methodDescriptor_SshService_Run);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SshCopyCommand,
 *   !proto.SshResponse>}
 */
const methodDescriptor_SshService_Copy = new grpc.web.MethodDescriptor(
  '/SshService/Copy',
  grpc.web.MethodType.UNARY,
  proto.SshCopyCommand,
  proto.SshResponse,
  /**
   * @param {!proto.SshCopyCommand} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SshResponse.deserializeBinary
);


/**
 * @param {!proto.SshCopyCommand} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SshResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SshResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SshServiceClient.prototype.copy =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SshService/Copy',
      request,
      metadata || {},
      methodDescriptor_SshService_Copy,
      callback);
};


/**
 * @param {!proto.SshCopyCommand} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SshResponse>}
 *     Promise that resolves to the response
 */
proto.SshServicePromiseClient.prototype.copy =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SshService/Copy',
      request,
      metadata || {},
      methodDescriptor_SshService_Copy);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ShareServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ShareServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ShareDefinition,
 *   !proto.ShareDefinition>}
 */
const methodDescriptor_ShareService_Create = new grpc.web.MethodDescriptor(
  '/ShareService/Create',
  grpc.web.MethodType.UNARY,
  proto.ShareDefinition,
  proto.ShareDefinition,
  /**
   * @param {!proto.ShareDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ShareDefinition.deserializeBinary
);


/**
 * @param {!proto.ShareDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ShareDefinition)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ShareDefinition>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/Create',
      request,
      metadata || {},
      methodDescriptor_ShareService_Create,
      callback);
};


/**
 * @param {!proto.ShareDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ShareDefinition>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/Create',
      request,
      metadata || {},
      methodDescriptor_ShareService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ShareService_Delete = new grpc.web.MethodDescriptor(
  '/ShareService/Delete',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/Delete',
      request,
      metadata || {},
      methodDescriptor_ShareService_Delete,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/Delete',
      request,
      metadata || {},
      methodDescriptor_ShareService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ShareList>}
 */
const methodDescriptor_ShareService_List = new grpc.web.MethodDescriptor(
  '/ShareService/List',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ShareList,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ShareList.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ShareList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ShareList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/List',
      request,
      metadata || {},
      methodDescriptor_ShareService_List,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ShareList>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/List',
      request,
      metadata || {},
      methodDescriptor_ShareService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ShareMountDefinition,
 *   !proto.ShareMountDefinition>}
 */
const methodDescriptor_ShareService_Mount = new grpc.web.MethodDescriptor(
  '/ShareService/Mount',
  grpc.web.MethodType.UNARY,
  proto.ShareMountDefinition,
  proto.ShareMountDefinition,
  /**
   * @param {!proto.ShareMountDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ShareMountDefinition.deserializeBinary
);


/**
 * @param {!proto.ShareMountDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ShareMountDefinition)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ShareMountDefinition>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.mount =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/Mount',
      request,
      metadata || {},
      methodDescriptor_ShareService_Mount,
      callback);
};


/**
 * @param {!proto.ShareMountDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ShareMountDefinition>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.mount =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/Mount',
      request,
      metadata || {},
      methodDescriptor_ShareService_Mount);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ShareMountDefinition,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ShareService_Unmount = new grpc.web.MethodDescriptor(
  '/ShareService/Unmount',
  grpc.web.MethodType.UNARY,
  proto.ShareMountDefinition,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ShareMountDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ShareMountDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.unmount =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/Unmount',
      request,
      metadata || {},
      methodDescriptor_ShareService_Unmount,
      callback);
};


/**
 * @param {!proto.ShareMountDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.unmount =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/Unmount',
      request,
      metadata || {},
      methodDescriptor_ShareService_Unmount);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ShareMountList>}
 */
const methodDescriptor_ShareService_Inspect = new grpc.web.MethodDescriptor(
  '/ShareService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ShareMountList,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ShareMountList.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ShareMountList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ShareMountList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ShareServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ShareService/Inspect',
      request,
      metadata || {},
      methodDescriptor_ShareService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ShareMountList>}
 *     Promise that resolves to the response
 */
proto.ShareServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ShareService/Inspect',
      request,
      metadata || {},
      methodDescriptor_ShareService_Inspect);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.JobServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.JobServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.JobDefinition,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_JobService_Stop = new grpc.web.MethodDescriptor(
  '/JobService/Stop',
  grpc.web.MethodType.UNARY,
  proto.JobDefinition,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.JobDefinition} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.JobDefinition} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.JobServiceClient.prototype.stop =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/JobService/Stop',
      request,
      metadata || {},
      methodDescriptor_JobService_Stop,
      callback);
};


/**
 * @param {!proto.JobDefinition} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.JobServicePromiseClient.prototype.stop =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/JobService/Stop',
      request,
      metadata || {},
      methodDescriptor_JobService_Stop);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.google.protobuf.Empty,
 *   !proto.JobList>}
 */
const methodDescriptor_JobService_List = new grpc.web.MethodDescriptor(
  '/JobService/List',
  grpc.web.MethodType.UNARY,
  google_protobuf_empty_pb.Empty,
  proto.JobList,
  /**
   * @param {!proto.google.protobuf.Empty} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.JobList.deserializeBinary
);


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.JobList)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.JobList>|undefined}
 *     The XHR Node Readable Stream
 */
proto.JobServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/JobService/List',
      request,
      metadata || {},
      methodDescriptor_JobService_List,
      callback);
};


/**
 * @param {!proto.google.protobuf.Empty} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.JobList>}
 *     Promise that resolves to the response
 */
proto.JobServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/JobService/List',
      request,
      metadata || {},
      methodDescriptor_JobService_List);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ClusterServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.ClusterServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ClusterListResponse>}
 */
const methodDescriptor_ClusterService_List = new grpc.web.MethodDescriptor(
  '/ClusterService/List',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ClusterListResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterListResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/List',
      request,
      metadata || {},
      methodDescriptor_ClusterService_List,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterListResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/List',
      request,
      metadata || {},
      methodDescriptor_ClusterService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ClusterResponse>}
 */
const methodDescriptor_ClusterService_Inspect = new grpc.web.MethodDescriptor(
  '/ClusterService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ClusterResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Inspect',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Inspect',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterCreateRequest,
 *   !proto.ClusterResponse>}
 */
const methodDescriptor_ClusterService_Create = new grpc.web.MethodDescriptor(
  '/ClusterService/Create',
  grpc.web.MethodType.UNARY,
  proto.ClusterCreateRequest,
  proto.ClusterResponse,
  /**
   * @param {!proto.ClusterCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterResponse.deserializeBinary
);


/**
 * @param {!proto.ClusterCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Create',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Create,
      callback);
};


/**
 * @param {!proto.ClusterCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Create',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterDeleteRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_Delete = new grpc.web.MethodDescriptor(
  '/ClusterService/Delete',
  grpc.web.MethodType.UNARY,
  proto.ClusterDeleteRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Delete',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Delete,
      callback);
};


/**
 * @param {!proto.ClusterDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Delete',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_Start = new grpc.web.MethodDescriptor(
  '/ClusterService/Start',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.start =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Start',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Start,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.start =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Start',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Start);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_Stop = new grpc.web.MethodDescriptor(
  '/ClusterService/Stop',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.stop =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Stop',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Stop,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.stop =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Stop',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Stop);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ClusterStateResponse>}
 */
const methodDescriptor_ClusterService_State = new grpc.web.MethodDescriptor(
  '/ClusterService/State',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ClusterStateResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterStateResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterStateResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterStateResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.state =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/State',
      request,
      metadata || {},
      methodDescriptor_ClusterService_State,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterStateResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.state =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/State',
      request,
      metadata || {},
      methodDescriptor_ClusterService_State);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterResizeRequest,
 *   !proto.ClusterNodeListResponse>}
 */
const methodDescriptor_ClusterService_Expand = new grpc.web.MethodDescriptor(
  '/ClusterService/Expand',
  grpc.web.MethodType.UNARY,
  proto.ClusterResizeRequest,
  proto.ClusterNodeListResponse,
  /**
   * @param {!proto.ClusterResizeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterNodeListResponse.deserializeBinary
);


/**
 * @param {!proto.ClusterResizeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterNodeListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterNodeListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.expand =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Expand',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Expand,
      callback);
};


/**
 * @param {!proto.ClusterResizeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterNodeListResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.expand =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Expand',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Expand);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterResizeRequest,
 *   !proto.ClusterNodeListResponse>}
 */
const methodDescriptor_ClusterService_Shrink = new grpc.web.MethodDescriptor(
  '/ClusterService/Shrink',
  grpc.web.MethodType.UNARY,
  proto.ClusterResizeRequest,
  proto.ClusterNodeListResponse,
  /**
   * @param {!proto.ClusterResizeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterNodeListResponse.deserializeBinary
);


/**
 * @param {!proto.ClusterResizeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterNodeListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterNodeListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.shrink =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/Shrink',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Shrink,
      callback);
};


/**
 * @param {!proto.ClusterResizeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterNodeListResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.shrink =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/Shrink',
      request,
      metadata || {},
      methodDescriptor_ClusterService_Shrink);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ClusterNodeListResponse>}
 */
const methodDescriptor_ClusterService_ListNodes = new grpc.web.MethodDescriptor(
  '/ClusterService/ListNodes',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ClusterNodeListResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterNodeListResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterNodeListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterNodeListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.listNodes =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/ListNodes',
      request,
      metadata || {},
      methodDescriptor_ClusterService_ListNodes,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterNodeListResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.listNodes =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/ListNodes',
      request,
      metadata || {},
      methodDescriptor_ClusterService_ListNodes);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.Host>}
 */
const methodDescriptor_ClusterService_InspectNode = new grpc.web.MethodDescriptor(
  '/ClusterService/InspectNode',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  proto.Host,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.inspectNode =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/InspectNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_InspectNode,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.inspectNode =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/InspectNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_InspectNode);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_DeleteNode = new grpc.web.MethodDescriptor(
  '/ClusterService/DeleteNode',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.deleteNode =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/DeleteNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_DeleteNode,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.deleteNode =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/DeleteNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_DeleteNode);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_StopNode = new grpc.web.MethodDescriptor(
  '/ClusterService/StopNode',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.stopNode =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StopNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StopNode,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.stopNode =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StopNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StopNode);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_StartNode = new grpc.web.MethodDescriptor(
  '/ClusterService/StartNode',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.startNode =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StartNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StartNode,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.startNode =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StartNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StartNode);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.HostStatus>}
 */
const methodDescriptor_ClusterService_StateNode = new grpc.web.MethodDescriptor(
  '/ClusterService/StateNode',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  proto.HostStatus,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostStatus.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostStatus)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostStatus>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.stateNode =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StateNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StateNode,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostStatus>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.stateNode =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StateNode',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StateNode);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.ClusterNodeListResponse>}
 */
const methodDescriptor_ClusterService_ListMasters = new grpc.web.MethodDescriptor(
  '/ClusterService/ListMasters',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.ClusterNodeListResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.ClusterNodeListResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.ClusterNodeListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.ClusterNodeListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.listMasters =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/ListMasters',
      request,
      metadata || {},
      methodDescriptor_ClusterService_ListMasters,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.ClusterNodeListResponse>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.listMasters =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/ListMasters',
      request,
      metadata || {},
      methodDescriptor_ClusterService_ListMasters);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.Host>}
 */
const methodDescriptor_ClusterService_InspectMaster = new grpc.web.MethodDescriptor(
  '/ClusterService/InspectMaster',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  proto.Host,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.inspectMaster =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/InspectMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_InspectMaster,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.inspectMaster =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/InspectMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_InspectMaster);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_StopMaster = new grpc.web.MethodDescriptor(
  '/ClusterService/StopMaster',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.stopMaster =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StopMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StopMaster,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.stopMaster =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StopMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StopMaster);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_ClusterService_StartMaster = new grpc.web.MethodDescriptor(
  '/ClusterService/StartMaster',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.startMaster =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StartMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StartMaster,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.startMaster =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StartMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StartMaster);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.ClusterNodeRequest,
 *   !proto.HostStatus>}
 */
const methodDescriptor_ClusterService_StateMaster = new grpc.web.MethodDescriptor(
  '/ClusterService/StateMaster',
  grpc.web.MethodType.UNARY,
  proto.ClusterNodeRequest,
  proto.HostStatus,
  /**
   * @param {!proto.ClusterNodeRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.HostStatus.deserializeBinary
);


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.HostStatus)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.HostStatus>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.stateMaster =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/StateMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StateMaster,
      callback);
};


/**
 * @param {!proto.ClusterNodeRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.HostStatus>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.stateMaster =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/StateMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_StateMaster);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.Host>}
 */
const methodDescriptor_ClusterService_FindAvailableMaster = new grpc.web.MethodDescriptor(
  '/ClusterService/FindAvailableMaster',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.Host,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.Host.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.Host)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.Host>|undefined}
 *     The XHR Node Readable Stream
 */
proto.ClusterServiceClient.prototype.findAvailableMaster =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/ClusterService/FindAvailableMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_FindAvailableMaster,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.Host>}
 *     Promise that resolves to the response
 */
proto.ClusterServicePromiseClient.prototype.findAvailableMaster =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/ClusterService/FindAvailableMaster',
      request,
      metadata || {},
      methodDescriptor_ClusterService_FindAvailableMaster);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.FeatureServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.FeatureServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureListRequest,
 *   !proto.FeatureListResponse>}
 */
const methodDescriptor_FeatureService_List = new grpc.web.MethodDescriptor(
  '/FeatureService/List',
  grpc.web.MethodType.UNARY,
  proto.FeatureListRequest,
  proto.FeatureListResponse,
  /**
   * @param {!proto.FeatureListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.FeatureListResponse.deserializeBinary
);


/**
 * @param {!proto.FeatureListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.FeatureListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.FeatureListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/List',
      request,
      metadata || {},
      methodDescriptor_FeatureService_List,
      callback);
};


/**
 * @param {!proto.FeatureListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.FeatureListResponse>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/List',
      request,
      metadata || {},
      methodDescriptor_FeatureService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureDetailRequest,
 *   !proto.FeatureDetailResponse>}
 */
const methodDescriptor_FeatureService_Inspect = new grpc.web.MethodDescriptor(
  '/FeatureService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.FeatureDetailRequest,
  proto.FeatureDetailResponse,
  /**
   * @param {!proto.FeatureDetailRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.FeatureDetailResponse.deserializeBinary
);


/**
 * @param {!proto.FeatureDetailRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.FeatureDetailResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.FeatureDetailResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/Inspect',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Inspect,
      callback);
};


/**
 * @param {!proto.FeatureDetailRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.FeatureDetailResponse>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/Inspect',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureDetailRequest,
 *   !proto.FeatureExportResponse>}
 */
const methodDescriptor_FeatureService_Export = new grpc.web.MethodDescriptor(
  '/FeatureService/Export',
  grpc.web.MethodType.UNARY,
  proto.FeatureDetailRequest,
  proto.FeatureExportResponse,
  /**
   * @param {!proto.FeatureDetailRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.FeatureExportResponse.deserializeBinary
);


/**
 * @param {!proto.FeatureDetailRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.FeatureExportResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.FeatureExportResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.export =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/Export',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Export,
      callback);
};


/**
 * @param {!proto.FeatureDetailRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.FeatureExportResponse>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.export =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/Export',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Export);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureActionRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_FeatureService_Check = new grpc.web.MethodDescriptor(
  '/FeatureService/Check',
  grpc.web.MethodType.UNARY,
  proto.FeatureActionRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.FeatureActionRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.check =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/Check',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Check,
      callback);
};


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.check =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/Check',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Check);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureActionRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_FeatureService_Add = new grpc.web.MethodDescriptor(
  '/FeatureService/Add',
  grpc.web.MethodType.UNARY,
  proto.FeatureActionRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.FeatureActionRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.add =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/Add',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Add,
      callback);
};


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.add =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/Add',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Add);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.FeatureActionRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_FeatureService_Remove = new grpc.web.MethodDescriptor(
  '/FeatureService/Remove',
  grpc.web.MethodType.UNARY,
  proto.FeatureActionRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.FeatureActionRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.FeatureServiceClient.prototype.remove =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/FeatureService/Remove',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Remove,
      callback);
};


/**
 * @param {!proto.FeatureActionRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.FeatureServicePromiseClient.prototype.remove =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/FeatureService/Remove',
      request,
      metadata || {},
      methodDescriptor_FeatureService_Remove);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SecurityGroupServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.SecurityGroupServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupRuleRequest,
 *   !proto.SecurityGroupResponse>}
 */
const methodDescriptor_SecurityGroupService_AddRule = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/AddRule',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupRuleRequest,
  proto.SecurityGroupResponse,
  /**
   * @param {!proto.SecurityGroupRuleRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupRuleRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.addRule =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/AddRule',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_AddRule,
      callback);
};


/**
 * @param {!proto.SecurityGroupRuleRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.addRule =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/AddRule',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_AddRule);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupBondsRequest,
 *   !proto.SecurityGroupBondsResponse>}
 */
const methodDescriptor_SecurityGroupService_Bonds = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Bonds',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupBondsRequest,
  proto.SecurityGroupBondsResponse,
  /**
   * @param {!proto.SecurityGroupBondsRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupBondsResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupBondsRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupBondsResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupBondsResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.bonds =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Bonds',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Bonds,
      callback);
};


/**
 * @param {!proto.SecurityGroupBondsRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupBondsResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.bonds =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Bonds',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Bonds);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SecurityGroupService_Clear = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Clear',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.clear =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Clear',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Clear,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.clear =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Clear',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Clear);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupCreateRequest,
 *   !proto.SecurityGroupResponse>}
 */
const methodDescriptor_SecurityGroupService_Create = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Create',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupCreateRequest,
  proto.SecurityGroupResponse,
  /**
   * @param {!proto.SecurityGroupCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Create',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Create,
      callback);
};


/**
 * @param {!proto.SecurityGroupCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Create',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupDeleteRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SecurityGroupService_Delete = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Delete',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupDeleteRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.SecurityGroupDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Delete',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Delete,
      callback);
};


/**
 * @param {!proto.SecurityGroupDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Delete',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupRuleDeleteRequest,
 *   !proto.SecurityGroupResponse>}
 */
const methodDescriptor_SecurityGroupService_DeleteRule = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/DeleteRule',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupRuleDeleteRequest,
  proto.SecurityGroupResponse,
  /**
   * @param {!proto.SecurityGroupRuleDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupRuleDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.deleteRule =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/DeleteRule',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_DeleteRule,
      callback);
};


/**
 * @param {!proto.SecurityGroupRuleDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.deleteRule =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/DeleteRule',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_DeleteRule);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.SecurityGroupResponse>}
 */
const methodDescriptor_SecurityGroupService_Inspect = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.SecurityGroupResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Inspect',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Inspect',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.SecurityGroupListRequest,
 *   !proto.SecurityGroupListResponse>}
 */
const methodDescriptor_SecurityGroupService_List = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/List',
  grpc.web.MethodType.UNARY,
  proto.SecurityGroupListRequest,
  proto.SecurityGroupListResponse,
  /**
   * @param {!proto.SecurityGroupListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.SecurityGroupListResponse.deserializeBinary
);


/**
 * @param {!proto.SecurityGroupListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.SecurityGroupListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.SecurityGroupListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/List',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_List,
      callback);
};


/**
 * @param {!proto.SecurityGroupListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.SecurityGroupListResponse>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/List',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SecurityGroupService_Reset = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Reset',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.reset =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Reset',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Reset,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.reset =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Reset',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Reset);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_SecurityGroupService_Sanitize = new grpc.web.MethodDescriptor(
  '/SecurityGroupService/Sanitize',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.SecurityGroupServiceClient.prototype.sanitize =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/SecurityGroupService/Sanitize',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Sanitize,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.SecurityGroupServicePromiseClient.prototype.sanitize =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/SecurityGroupService/Sanitize',
      request,
      metadata || {},
      methodDescriptor_SecurityGroupService_Sanitize);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.PublicIPServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.PublicIPServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.PublicIPCreateRequest,
 *   !proto.PublicIPResponse>}
 */
const methodDescriptor_PublicIPService_Create = new grpc.web.MethodDescriptor(
  '/PublicIPService/Create',
  grpc.web.MethodType.UNARY,
  proto.PublicIPCreateRequest,
  proto.PublicIPResponse,
  /**
   * @param {!proto.PublicIPCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.PublicIPResponse.deserializeBinary
);


/**
 * @param {!proto.PublicIPCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.PublicIPResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.PublicIPResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.PublicIPServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/PublicIPService/Create',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Create,
      callback);
};


/**
 * @param {!proto.PublicIPCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.PublicIPResponse>}
 *     Promise that resolves to the response
 */
proto.PublicIPServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/PublicIPService/Create',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.PublicIPDeleteRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_PublicIPService_Delete = new grpc.web.MethodDescriptor(
  '/PublicIPService/Delete',
  grpc.web.MethodType.UNARY,
  proto.PublicIPDeleteRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.PublicIPDeleteRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.PublicIPDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.PublicIPServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/PublicIPService/Delete',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Delete,
      callback);
};


/**
 * @param {!proto.PublicIPDeleteRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.PublicIPServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/PublicIPService/Delete',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.Reference,
 *   !proto.PublicIPResponse>}
 */
const methodDescriptor_PublicIPService_Inspect = new grpc.web.MethodDescriptor(
  '/PublicIPService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.Reference,
  proto.PublicIPResponse,
  /**
   * @param {!proto.Reference} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.PublicIPResponse.deserializeBinary
);


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.PublicIPResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.PublicIPResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.PublicIPServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/PublicIPService/Inspect',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Inspect,
      callback);
};


/**
 * @param {!proto.Reference} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.PublicIPResponse>}
 *     Promise that resolves to the response
 */
proto.PublicIPServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/PublicIPService/Inspect',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_Inspect);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.PublicIPListRequest,
 *   !proto.PublicIPListResponse>}
 */
const methodDescriptor_PublicIPService_List = new grpc.web.MethodDescriptor(
  '/PublicIPService/List',
  grpc.web.MethodType.UNARY,
  proto.PublicIPListRequest,
  proto.PublicIPListResponse,
  /**
   * @param {!proto.PublicIPListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.PublicIPListResponse.deserializeBinary
);


/**
 * @param {!proto.PublicIPListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.PublicIPListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.PublicIPListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.PublicIPServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/PublicIPService/List',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_List,
      callback);
};


/**
 * @param {!proto.PublicIPListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.PublicIPListResponse>}
 *     Promise that resolves to the response
 */
proto.PublicIPServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/PublicIPService/List',
      request,
      metadata || {},
      methodDescriptor_PublicIPService_List);
};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.LabelServiceClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.LabelServicePromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelCreateRequest,
 *   !proto.LabelInspectResponse>}
 */
const methodDescriptor_LabelService_Create = new grpc.web.MethodDescriptor(
  '/LabelService/Create',
  grpc.web.MethodType.UNARY,
  proto.LabelCreateRequest,
  proto.LabelInspectResponse,
  /**
   * @param {!proto.LabelCreateRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.LabelInspectResponse.deserializeBinary
);


/**
 * @param {!proto.LabelCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.LabelInspectResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.LabelInspectResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.LabelServiceClient.prototype.create =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/LabelService/Create',
      request,
      metadata || {},
      methodDescriptor_LabelService_Create,
      callback);
};


/**
 * @param {!proto.LabelCreateRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.LabelInspectResponse>}
 *     Promise that resolves to the response
 */
proto.LabelServicePromiseClient.prototype.create =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/LabelService/Create',
      request,
      metadata || {},
      methodDescriptor_LabelService_Create);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelInspectRequest,
 *   !proto.google.protobuf.Empty>}
 */
const methodDescriptor_LabelService_Delete = new grpc.web.MethodDescriptor(
  '/LabelService/Delete',
  grpc.web.MethodType.UNARY,
  proto.LabelInspectRequest,
  google_protobuf_empty_pb.Empty,
  /**
   * @param {!proto.LabelInspectRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  google_protobuf_empty_pb.Empty.deserializeBinary
);


/**
 * @param {!proto.LabelInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.google.protobuf.Empty)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.google.protobuf.Empty>|undefined}
 *     The XHR Node Readable Stream
 */
proto.LabelServiceClient.prototype.delete =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/LabelService/Delete',
      request,
      metadata || {},
      methodDescriptor_LabelService_Delete,
      callback);
};


/**
 * @param {!proto.LabelInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.google.protobuf.Empty>}
 *     Promise that resolves to the response
 */
proto.LabelServicePromiseClient.prototype.delete =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/LabelService/Delete',
      request,
      metadata || {},
      methodDescriptor_LabelService_Delete);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelListRequest,
 *   !proto.LabelListResponse>}
 */
const methodDescriptor_LabelService_List = new grpc.web.MethodDescriptor(
  '/LabelService/List',
  grpc.web.MethodType.UNARY,
  proto.LabelListRequest,
  proto.LabelListResponse,
  /**
   * @param {!proto.LabelListRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.LabelListResponse.deserializeBinary
);


/**
 * @param {!proto.LabelListRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.LabelListResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.LabelListResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.LabelServiceClient.prototype.list =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/LabelService/List',
      request,
      metadata || {},
      methodDescriptor_LabelService_List,
      callback);
};


/**
 * @param {!proto.LabelListRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.LabelListResponse>}
 *     Promise that resolves to the response
 */
proto.LabelServicePromiseClient.prototype.list =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/LabelService/List',
      request,
      metadata || {},
      methodDescriptor_LabelService_List);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.LabelInspectRequest,
 *   !proto.LabelInspectResponse>}
 */
const methodDescriptor_LabelService_Inspect = new grpc.web.MethodDescriptor(
  '/LabelService/Inspect',
  grpc.web.MethodType.UNARY,
  proto.LabelInspectRequest,
  proto.LabelInspectResponse,
  /**
   * @param {!proto.LabelInspectRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.LabelInspectResponse.deserializeBinary
);


/**
 * @param {!proto.LabelInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.LabelInspectResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.LabelInspectResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.LabelServiceClient.prototype.inspect =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/LabelService/Inspect',
      request,
      metadata || {},
      methodDescriptor_LabelService_Inspect,
      callback);
};


/**
 * @param {!proto.LabelInspectRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.LabelInspectResponse>}
 *     Promise that resolves to the response
 */
proto.LabelServicePromiseClient.prototype.inspect =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/LabelService/Inspect',
      request,
      metadata || {},
      methodDescriptor_LabelService_Inspect);
};


module.exports = proto;

