// source: safescale.proto
/**
 * @fileoverview
 * @enhanceable
 * @suppress {missingRequire} reports error on implicit type usages.
 * @suppress {messageConventions} JS Compiler reports an error if a variable or
 *     field starts with 'MSG_' and isn't a translatable message.
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck

var jspb = require('google-protobuf');
var goog = jspb;
var global = (function() { return this || window || global || self || Function('return this')(); }).call(null);

var google_protobuf_empty_pb = require('google-protobuf/google/protobuf/empty_pb.js');
goog.object.extend(proto, google_protobuf_empty_pb);
var google_protobuf_timestamp_pb = require('google-protobuf/google/protobuf/timestamp_pb.js');
goog.object.extend(proto, google_protobuf_timestamp_pb);
goog.exportSymbol('proto.BucketDownloadResponse', null, global);
goog.exportSymbol('proto.BucketListRequest', null, global);
goog.exportSymbol('proto.BucketListResponse', null, global);
goog.exportSymbol('proto.BucketMount', null, global);
goog.exportSymbol('proto.BucketMountRequest', null, global);
goog.exportSymbol('proto.BucketRequest', null, global);
goog.exportSymbol('proto.BucketResponse', null, global);
goog.exportSymbol('proto.ClientID', null, global);
goog.exportSymbol('proto.ClientRequest', null, global);
goog.exportSymbol('proto.ClusterComplexity', null, global);
goog.exportSymbol('proto.ClusterComposite', null, global);
goog.exportSymbol('proto.ClusterControlplane', null, global);
goog.exportSymbol('proto.ClusterCreateRequest', null, global);
goog.exportSymbol('proto.ClusterDefaults', null, global);
goog.exportSymbol('proto.ClusterDeleteRequest', null, global);
goog.exportSymbol('proto.ClusterFlavor', null, global);
goog.exportSymbol('proto.ClusterHostOptions', null, global);
goog.exportSymbol('proto.ClusterIdentity', null, global);
goog.exportSymbol('proto.ClusterListResponse', null, global);
goog.exportSymbol('proto.ClusterNetwork', null, global);
goog.exportSymbol('proto.ClusterNodeListResponse', null, global);
goog.exportSymbol('proto.ClusterNodeRequest', null, global);
goog.exportSymbol('proto.ClusterResizeRequest', null, global);
goog.exportSymbol('proto.ClusterResponse', null, global);
goog.exportSymbol('proto.ClusterState', null, global);
goog.exportSymbol('proto.ClusterStateResponse', null, global);
goog.exportSymbol('proto.FeatureActionRequest', null, global);
goog.exportSymbol('proto.FeatureDetailRequest', null, global);
goog.exportSymbol('proto.FeatureDetailResponse', null, global);
goog.exportSymbol('proto.FeatureExportResponse', null, global);
goog.exportSymbol('proto.FeatureListRequest', null, global);
goog.exportSymbol('proto.FeatureListResponse', null, global);
goog.exportSymbol('proto.FeatureResponse', null, global);
goog.exportSymbol('proto.FeatureSettings', null, global);
goog.exportSymbol('proto.FeatureTargetType', null, global);
goog.exportSymbol('proto.GatewayDefinition', null, global);
goog.exportSymbol('proto.Host', null, global);
goog.exportSymbol('proto.HostDefinition', null, global);
goog.exportSymbol('proto.HostLabelRequest', null, global);
goog.exportSymbol('proto.HostLabelResponse', null, global);
goog.exportSymbol('proto.HostList', null, global);
goog.exportSymbol('proto.HostListRequest', null, global);
goog.exportSymbol('proto.HostSizing', null, global);
goog.exportSymbol('proto.HostState', null, global);
goog.exportSymbol('proto.HostStatus', null, global);
goog.exportSymbol('proto.HostTemplate', null, global);
goog.exportSymbol('proto.Image', null, global);
goog.exportSymbol('proto.ImageList', null, global);
goog.exportSymbol('proto.ImageListRequest', null, global);
goog.exportSymbol('proto.JobDefinition', null, global);
goog.exportSymbol('proto.JobList', null, global);
goog.exportSymbol('proto.KeyValue', null, global);
goog.exportSymbol('proto.LabelBindRequest', null, global);
goog.exportSymbol('proto.LabelBoundsRequest', null, global);
goog.exportSymbol('proto.LabelCreateRequest', null, global);
goog.exportSymbol('proto.LabelHostResponse', null, global);
goog.exportSymbol('proto.LabelInspectRequest', null, global);
goog.exportSymbol('proto.LabelInspectResponse', null, global);
goog.exportSymbol('proto.LabelListRequest', null, global);
goog.exportSymbol('proto.LabelListResponse', null, global);
goog.exportSymbol('proto.NFSExportOptions', null, global);
goog.exportSymbol('proto.Network', null, global);
goog.exportSymbol('proto.NetworkCreateRequest', null, global);
goog.exportSymbol('proto.NetworkDeleteRequest', null, global);
goog.exportSymbol('proto.NetworkList', null, global);
goog.exportSymbol('proto.NetworkListRequest', null, global);
goog.exportSymbol('proto.NetworkState', null, global);
goog.exportSymbol('proto.PriceInfo', null, global);
goog.exportSymbol('proto.PublicIPBindRequest', null, global);
goog.exportSymbol('proto.PublicIPCreateRequest', null, global);
goog.exportSymbol('proto.PublicIPDeleteRequest', null, global);
goog.exportSymbol('proto.PublicIPListRequest', null, global);
goog.exportSymbol('proto.PublicIPListResponse', null, global);
goog.exportSymbol('proto.PublicIPResponse', null, global);
goog.exportSymbol('proto.Reference', null, global);
goog.exportSymbol('proto.ScanResult', null, global);
goog.exportSymbol('proto.ScanResultList', null, global);
goog.exportSymbol('proto.ScannedInfo', null, global);
goog.exportSymbol('proto.SecurityGroupBond', null, global);
goog.exportSymbol('proto.SecurityGroupBondsRequest', null, global);
goog.exportSymbol('proto.SecurityGroupBondsResponse', null, global);
goog.exportSymbol('proto.SecurityGroupCreateRequest', null, global);
goog.exportSymbol('proto.SecurityGroupDeleteRequest', null, global);
goog.exportSymbol('proto.SecurityGroupHostBindRequest', null, global);
goog.exportSymbol('proto.SecurityGroupListRequest', null, global);
goog.exportSymbol('proto.SecurityGroupListResponse', null, global);
goog.exportSymbol('proto.SecurityGroupResponse', null, global);
goog.exportSymbol('proto.SecurityGroupRule', null, global);
goog.exportSymbol('proto.SecurityGroupRuleDeleteRequest', null, global);
goog.exportSymbol('proto.SecurityGroupRuleDirection', null, global);
goog.exportSymbol('proto.SecurityGroupRuleEtherType', null, global);
goog.exportSymbol('proto.SecurityGroupRuleRequest', null, global);
goog.exportSymbol('proto.SecurityGroupState', null, global);
goog.exportSymbol('proto.SecurityGroupSubnetBindRequest', null, global);
goog.exportSymbol('proto.ShareDefinition', null, global);
goog.exportSymbol('proto.ShareList', null, global);
goog.exportSymbol('proto.ShareMountDefinition', null, global);
goog.exportSymbol('proto.ShareMountList', null, global);
goog.exportSymbol('proto.SshCommand', null, global);
goog.exportSymbol('proto.SshConfig', null, global);
goog.exportSymbol('proto.SshCopyCommand', null, global);
goog.exportSymbol('proto.SshResponse', null, global);
goog.exportSymbol('proto.Subnet', null, global);
goog.exportSymbol('proto.SubnetCreateRequest', null, global);
goog.exportSymbol('proto.SubnetDeleteRequest', null, global);
goog.exportSymbol('proto.SubnetInspectRequest', null, global);
goog.exportSymbol('proto.SubnetList', null, global);
goog.exportSymbol('proto.SubnetListRequest', null, global);
goog.exportSymbol('proto.SubnetSecurityGroupBondsRequest', null, global);
goog.exportSymbol('proto.SubnetState', null, global);
goog.exportSymbol('proto.TemplateInspectRequest', null, global);
goog.exportSymbol('proto.TemplateList', null, global);
goog.exportSymbol('proto.TemplateListRequest', null, global);
goog.exportSymbol('proto.TemplateMatchRequest', null, global);
goog.exportSymbol('proto.Tenant', null, global);
goog.exportSymbol('proto.TenantCleanupRequest', null, global);
goog.exportSymbol('proto.TenantCompute', null, global);
goog.exportSymbol('proto.TenantIdentity', null, global);
goog.exportSymbol('proto.TenantInspectRequest', null, global);
goog.exportSymbol('proto.TenantInspectResponse', null, global);
goog.exportSymbol('proto.TenantList', null, global);
goog.exportSymbol('proto.TenantMetadata', null, global);
goog.exportSymbol('proto.TenantName', null, global);
goog.exportSymbol('proto.TenantNetwork', null, global);
goog.exportSymbol('proto.TenantObjectStorage', null, global);
goog.exportSymbol('proto.TenantScanRequest', null, global);
goog.exportSymbol('proto.TenantUpgradeRequest', null, global);
goog.exportSymbol('proto.TenantUpgradeResponse', null, global);
goog.exportSymbol('proto.VirtualIp', null, global);
goog.exportSymbol('proto.VolumeAttachmentRequest', null, global);
goog.exportSymbol('proto.VolumeAttachmentResponse', null, global);
goog.exportSymbol('proto.VolumeCreateRequest', null, global);
goog.exportSymbol('proto.VolumeDetachmentRequest', null, global);
goog.exportSymbol('proto.VolumeInspectResponse', null, global);
goog.exportSymbol('proto.VolumeListRequest', null, global);
goog.exportSymbol('proto.VolumeListResponse', null, global);
goog.exportSymbol('proto.VolumeSpeed', null, global);
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Reference = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.Reference, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Reference.displayName = 'proto.Reference';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClientID = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClientID, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClientID.displayName = 'proto.ClientID';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClientRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClientRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClientRequest.displayName = 'proto.ClientRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Tenant = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.Tenant, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Tenant.displayName = 'proto.Tenant';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.TenantList.repeatedFields_, null);
};
goog.inherits(proto.TenantList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantList.displayName = 'proto.TenantList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantName = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantName, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantName.displayName = 'proto.TenantName';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantCleanupRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantCleanupRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantCleanupRequest.displayName = 'proto.TenantCleanupRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantUpgradeRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantUpgradeRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantUpgradeRequest.displayName = 'proto.TenantUpgradeRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantScanRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.TenantScanRequest.repeatedFields_, null);
};
goog.inherits(proto.TenantScanRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantScanRequest.displayName = 'proto.TenantScanRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ScanResult = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ScanResult, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ScanResult.displayName = 'proto.ScanResult';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ScanResultList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ScanResultList.repeatedFields_, null);
};
goog.inherits(proto.ScanResultList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ScanResultList.displayName = 'proto.ScanResultList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantInspectRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantInspectRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantInspectRequest.displayName = 'proto.TenantInspectRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.KeyValue = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.KeyValue, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.KeyValue.displayName = 'proto.KeyValue';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantIdentity = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantIdentity, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantIdentity.displayName = 'proto.TenantIdentity';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantCompute = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.TenantCompute.repeatedFields_, null);
};
goog.inherits(proto.TenantCompute, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantCompute.displayName = 'proto.TenantCompute';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantNetwork = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantNetwork, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantNetwork.displayName = 'proto.TenantNetwork';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantObjectStorage = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantObjectStorage, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantObjectStorage.displayName = 'proto.TenantObjectStorage';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantMetadata = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantMetadata, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantMetadata.displayName = 'proto.TenantMetadata';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantInspectResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TenantInspectResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantInspectResponse.displayName = 'proto.TenantInspectResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TenantUpgradeResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.TenantUpgradeResponse.repeatedFields_, null);
};
goog.inherits(proto.TenantUpgradeResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TenantUpgradeResponse.displayName = 'proto.TenantUpgradeResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Image = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.Image, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Image.displayName = 'proto.Image';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ImageList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ImageList.repeatedFields_, null);
};
goog.inherits(proto.ImageList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ImageList.displayName = 'proto.ImageList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ImageListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ImageListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ImageListRequest.displayName = 'proto.ImageListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.NetworkCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.NetworkCreateRequest.repeatedFields_, null);
};
goog.inherits(proto.NetworkCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.NetworkCreateRequest.displayName = 'proto.NetworkCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Network = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.Network.repeatedFields_, null);
};
goog.inherits(proto.Network, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Network.displayName = 'proto.Network';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.NetworkList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.NetworkList.repeatedFields_, null);
};
goog.inherits(proto.NetworkList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.NetworkList.displayName = 'proto.NetworkList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.NetworkListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.NetworkListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.NetworkListRequest.displayName = 'proto.NetworkListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.NetworkDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.NetworkDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.NetworkDeleteRequest.displayName = 'proto.NetworkDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VirtualIp = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.VirtualIp.repeatedFields_, null);
};
goog.inherits(proto.VirtualIp, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VirtualIp.displayName = 'proto.VirtualIp';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SubnetCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetCreateRequest.displayName = 'proto.SubnetCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.GatewayDefinition = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.GatewayDefinition, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.GatewayDefinition.displayName = 'proto.GatewayDefinition';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetInspectRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SubnetInspectRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetInspectRequest.displayName = 'proto.SubnetInspectRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SubnetDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetDeleteRequest.displayName = 'proto.SubnetDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Subnet = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.Subnet.repeatedFields_, null);
};
goog.inherits(proto.Subnet, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Subnet.displayName = 'proto.Subnet';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SubnetList.repeatedFields_, null);
};
goog.inherits(proto.SubnetList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetList.displayName = 'proto.SubnetList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SubnetListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetListRequest.displayName = 'proto.SubnetListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SubnetSecurityGroupBondsRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SubnetSecurityGroupBondsRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SubnetSecurityGroupBondsRequest.displayName = 'proto.SubnetSecurityGroupBondsRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostSizing = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostSizing, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostSizing.displayName = 'proto.HostSizing';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostDefinition = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.HostDefinition.repeatedFields_, null);
};
goog.inherits(proto.HostDefinition, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostDefinition.displayName = 'proto.HostDefinition';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.Host = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.Host.repeatedFields_, null);
};
goog.inherits(proto.Host, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.Host.displayName = 'proto.Host';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostStatus = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostStatus, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostStatus.displayName = 'proto.HostStatus';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.HostList.repeatedFields_, null);
};
goog.inherits(proto.HostList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostList.displayName = 'proto.HostList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SshConfig = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SshConfig, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SshConfig.displayName = 'proto.SshConfig';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostListRequest.displayName = 'proto.HostListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostLabelRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostLabelRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostLabelRequest.displayName = 'proto.HostLabelRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostLabelResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostLabelResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostLabelResponse.displayName = 'proto.HostLabelResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.HostTemplate = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.HostTemplate, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.HostTemplate.displayName = 'proto.HostTemplate';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ScannedInfo = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ScannedInfo.repeatedFields_, null);
};
goog.inherits(proto.ScannedInfo, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ScannedInfo.displayName = 'proto.ScannedInfo';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PriceInfo = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PriceInfo, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PriceInfo.displayName = 'proto.PriceInfo';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TemplateList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.TemplateList.repeatedFields_, null);
};
goog.inherits(proto.TemplateList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TemplateList.displayName = 'proto.TemplateList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TemplateListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TemplateListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TemplateListRequest.displayName = 'proto.TemplateListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TemplateMatchRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TemplateMatchRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TemplateMatchRequest.displayName = 'proto.TemplateMatchRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.TemplateInspectRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.TemplateInspectRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.TemplateInspectRequest.displayName = 'proto.TemplateInspectRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.VolumeCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeCreateRequest.displayName = 'proto.VolumeCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeDetachmentRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.VolumeDetachmentRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeDetachmentRequest.displayName = 'proto.VolumeDetachmentRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeInspectResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.VolumeInspectResponse.repeatedFields_, null);
};
goog.inherits(proto.VolumeInspectResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeInspectResponse.displayName = 'proto.VolumeInspectResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeAttachmentRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.VolumeAttachmentRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeAttachmentRequest.displayName = 'proto.VolumeAttachmentRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeAttachmentResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.VolumeAttachmentResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeAttachmentResponse.displayName = 'proto.VolumeAttachmentResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.VolumeListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeListRequest.displayName = 'proto.VolumeListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.VolumeListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.VolumeListResponse.repeatedFields_, null);
};
goog.inherits(proto.VolumeListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.VolumeListResponse.displayName = 'proto.VolumeListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketMount = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.BucketMount, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketMount.displayName = 'proto.BucketMount';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.BucketRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketRequest.displayName = 'proto.BucketRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.BucketResponse.repeatedFields_, null);
};
goog.inherits(proto.BucketResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketResponse.displayName = 'proto.BucketResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.BucketListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketListRequest.displayName = 'proto.BucketListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.BucketListResponse.repeatedFields_, null);
};
goog.inherits(proto.BucketListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketListResponse.displayName = 'proto.BucketListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketDownloadResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.BucketDownloadResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketDownloadResponse.displayName = 'proto.BucketDownloadResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.BucketMountRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.BucketMountRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.BucketMountRequest.displayName = 'proto.BucketMountRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SshCommand = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SshCommand, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SshCommand.displayName = 'proto.SshCommand';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SshCopyCommand = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SshCopyCommand, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SshCopyCommand.displayName = 'proto.SshCopyCommand';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SshResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SshResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SshResponse.displayName = 'proto.SshResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.NFSExportOptions = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.NFSExportOptions, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.NFSExportOptions.displayName = 'proto.NFSExportOptions';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ShareDefinition = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ShareDefinition.repeatedFields_, null);
};
goog.inherits(proto.ShareDefinition, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ShareDefinition.displayName = 'proto.ShareDefinition';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ShareList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ShareList.repeatedFields_, null);
};
goog.inherits(proto.ShareList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ShareList.displayName = 'proto.ShareList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ShareMountDefinition = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ShareMountDefinition, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ShareMountDefinition.displayName = 'proto.ShareMountDefinition';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ShareMountList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ShareMountList.repeatedFields_, null);
};
goog.inherits(proto.ShareMountList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ShareMountList.displayName = 'proto.ShareMountList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.JobDefinition = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.JobDefinition, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.JobDefinition.displayName = 'proto.JobDefinition';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.JobList = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.JobList.repeatedFields_, null);
};
goog.inherits(proto.JobList, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.JobList.displayName = 'proto.JobList';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterStateResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterStateResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterStateResponse.displayName = 'proto.ClusterStateResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterListResponse.repeatedFields_, null);
};
goog.inherits(proto.ClusterListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterListResponse.displayName = 'proto.ClusterListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterCreateRequest.repeatedFields_, null);
};
goog.inherits(proto.ClusterCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterCreateRequest.displayName = 'proto.ClusterCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterResizeRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterResizeRequest.repeatedFields_, null);
};
goog.inherits(proto.ClusterResizeRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterResizeRequest.displayName = 'proto.ClusterResizeRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterDeleteRequest.displayName = 'proto.ClusterDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterIdentity = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterIdentity, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterIdentity.displayName = 'proto.ClusterIdentity';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterHostOptions = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterHostOptions, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterHostOptions.displayName = 'proto.ClusterHostOptions';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterDefaults = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterDefaults.repeatedFields_, null);
};
goog.inherits(proto.ClusterDefaults, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterDefaults.displayName = 'proto.ClusterDefaults';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterControlplane = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterControlplane, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterControlplane.displayName = 'proto.ClusterControlplane';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterComposite = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterComposite.repeatedFields_, null);
};
goog.inherits(proto.ClusterComposite, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterComposite.displayName = 'proto.ClusterComposite';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterNetwork = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterNetwork, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterNetwork.displayName = 'proto.ClusterNetwork';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterResponse.repeatedFields_, null);
};
goog.inherits(proto.ClusterResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterResponse.displayName = 'proto.ClusterResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterNodeListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.ClusterNodeListResponse.repeatedFields_, null);
};
goog.inherits(proto.ClusterNodeListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterNodeListResponse.displayName = 'proto.ClusterNodeListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.ClusterNodeRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.ClusterNodeRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.ClusterNodeRequest.displayName = 'proto.ClusterNodeRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.FeatureResponse.repeatedFields_, null);
};
goog.inherits(proto.FeatureResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureResponse.displayName = 'proto.FeatureResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.FeatureListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureListRequest.displayName = 'proto.FeatureListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.FeatureListResponse.repeatedFields_, null);
};
goog.inherits(proto.FeatureListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureListResponse.displayName = 'proto.FeatureListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureDetailRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.FeatureDetailRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureDetailRequest.displayName = 'proto.FeatureDetailRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureDetailResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.FeatureDetailResponse.repeatedFields_, null);
};
goog.inherits(proto.FeatureDetailResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureDetailResponse.displayName = 'proto.FeatureDetailResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureExportResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.FeatureExportResponse.repeatedFields_, null);
};
goog.inherits(proto.FeatureExportResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureExportResponse.displayName = 'proto.FeatureExportResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureSettings = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.FeatureSettings, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureSettings.displayName = 'proto.FeatureSettings';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.FeatureActionRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.FeatureActionRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.FeatureActionRequest.displayName = 'proto.FeatureActionRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupRule = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SecurityGroupRule.repeatedFields_, null);
};
goog.inherits(proto.SecurityGroupRule, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupRule.displayName = 'proto.SecurityGroupRule';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupRuleRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupRuleRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupRuleRequest.displayName = 'proto.SecurityGroupRuleRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupRuleDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupRuleDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupRuleDeleteRequest.displayName = 'proto.SecurityGroupRuleDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SecurityGroupCreateRequest.repeatedFields_, null);
};
goog.inherits(proto.SecurityGroupCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupCreateRequest.displayName = 'proto.SecurityGroupCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SecurityGroupResponse.repeatedFields_, null);
};
goog.inherits(proto.SecurityGroupResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupResponse.displayName = 'proto.SecurityGroupResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupListRequest.displayName = 'proto.SecurityGroupListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SecurityGroupListResponse.repeatedFields_, null);
};
goog.inherits(proto.SecurityGroupListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupListResponse.displayName = 'proto.SecurityGroupListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupHostBindRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupHostBindRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupHostBindRequest.displayName = 'proto.SecurityGroupHostBindRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupSubnetBindRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupSubnetBindRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupSubnetBindRequest.displayName = 'proto.SecurityGroupSubnetBindRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupBondsRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupBondsRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupBondsRequest.displayName = 'proto.SecurityGroupBondsRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupBond = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupBond, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupBond.displayName = 'proto.SecurityGroupBond';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupBondsResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.SecurityGroupBondsResponse.repeatedFields_, null);
};
goog.inherits(proto.SecurityGroupBondsResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupBondsResponse.displayName = 'proto.SecurityGroupBondsResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.SecurityGroupDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.SecurityGroupDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.SecurityGroupDeleteRequest.displayName = 'proto.SecurityGroupDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PublicIPCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPCreateRequest.displayName = 'proto.PublicIPCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PublicIPResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPResponse.displayName = 'proto.PublicIPResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PublicIPListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPListRequest.displayName = 'proto.PublicIPListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.PublicIPListResponse.repeatedFields_, null);
};
goog.inherits(proto.PublicIPListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPListResponse.displayName = 'proto.PublicIPListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPDeleteRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PublicIPDeleteRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPDeleteRequest.displayName = 'proto.PublicIPDeleteRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.PublicIPBindRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.PublicIPBindRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.PublicIPBindRequest.displayName = 'proto.PublicIPBindRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelCreateRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelCreateRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelCreateRequest.displayName = 'proto.LabelCreateRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelInspectRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelInspectRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelInspectRequest.displayName = 'proto.LabelInspectRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelInspectResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.LabelInspectResponse.repeatedFields_, null);
};
goog.inherits(proto.LabelInspectResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelInspectResponse.displayName = 'proto.LabelInspectResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelListRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelListRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelListRequest.displayName = 'proto.LabelListRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelListResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.LabelListResponse.repeatedFields_, null);
};
goog.inherits(proto.LabelListResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelListResponse.displayName = 'proto.LabelListResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelHostResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelHostResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelHostResponse.displayName = 'proto.LabelHostResponse';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelBindRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelBindRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelBindRequest.displayName = 'proto.LabelBindRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.LabelBoundsRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.LabelBoundsRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.LabelBoundsRequest.displayName = 'proto.LabelBoundsRequest';
}



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Reference.prototype.toObject = function(opt_includeInstance) {
  return proto.Reference.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Reference} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Reference.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantId: jspb.Message.getFieldWithDefault(msg, 1, ""),
    id: jspb.Message.getFieldWithDefault(msg, 2, ""),
    name: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Reference}
 */
proto.Reference.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Reference;
  return proto.Reference.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Reference} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Reference}
 */
proto.Reference.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Reference.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Reference.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Reference} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Reference.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string tenant_id = 1;
 * @return {string}
 */
proto.Reference.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Reference} returns this
 */
proto.Reference.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string id = 2;
 * @return {string}
 */
proto.Reference.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Reference} returns this
 */
proto.Reference.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string name = 3;
 * @return {string}
 */
proto.Reference.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.Reference} returns this
 */
proto.Reference.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClientID.prototype.toObject = function(opt_includeInstance) {
  return proto.ClientID.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClientID} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClientID.toObject = function(includeInstance, msg) {
  var f, obj = {
    hostname: jspb.Message.getFieldWithDefault(msg, 1, ""),
    userid: jspb.Message.getFieldWithDefault(msg, 2, ""),
    processId: jspb.Message.getFieldWithDefault(msg, 3, ""),
    parentProcessId: jspb.Message.getFieldWithDefault(msg, 4, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClientID}
 */
proto.ClientID.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClientID;
  return proto.ClientID.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClientID} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClientID}
 */
proto.ClientID.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setHostname(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setUserid(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setProcessId(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setParentProcessId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClientID.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClientID.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClientID} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClientID.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHostname();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getUserid();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getProcessId();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getParentProcessId();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
};


/**
 * optional string hostname = 1;
 * @return {string}
 */
proto.ClientID.prototype.getHostname = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClientID} returns this
 */
proto.ClientID.prototype.setHostname = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string userid = 2;
 * @return {string}
 */
proto.ClientID.prototype.getUserid = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClientID} returns this
 */
proto.ClientID.prototype.setUserid = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string process_id = 3;
 * @return {string}
 */
proto.ClientID.prototype.getProcessId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClientID} returns this
 */
proto.ClientID.prototype.setProcessId = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string parent_process_id = 4;
 * @return {string}
 */
proto.ClientID.prototype.getParentProcessId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClientID} returns this
 */
proto.ClientID.prototype.setParentProcessId = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClientRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ClientRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClientRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClientRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    clientId: (f = msg.getClientId()) && proto.ClientID.toObject(includeInstance, f),
    timestamp: (f = msg.getTimestamp()) && google_protobuf_timestamp_pb.Timestamp.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClientRequest}
 */
proto.ClientRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClientRequest;
  return proto.ClientRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClientRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClientRequest}
 */
proto.ClientRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ClientID;
      reader.readMessage(value,proto.ClientID.deserializeBinaryFromReader);
      msg.setClientId(value);
      break;
    case 2:
      var value = new google_protobuf_timestamp_pb.Timestamp;
      reader.readMessage(value,google_protobuf_timestamp_pb.Timestamp.deserializeBinaryFromReader);
      msg.setTimestamp(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClientRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClientRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClientRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClientRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getClientId();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.ClientID.serializeBinaryToWriter
    );
  }
  f = message.getTimestamp();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      google_protobuf_timestamp_pb.Timestamp.serializeBinaryToWriter
    );
  }
};


/**
 * optional ClientID client_id = 1;
 * @return {?proto.ClientID}
 */
proto.ClientRequest.prototype.getClientId = function() {
  return /** @type{?proto.ClientID} */ (
    jspb.Message.getWrapperField(this, proto.ClientID, 1));
};


/**
 * @param {?proto.ClientID|undefined} value
 * @return {!proto.ClientRequest} returns this
*/
proto.ClientRequest.prototype.setClientId = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClientRequest} returns this
 */
proto.ClientRequest.prototype.clearClientId = function() {
  return this.setClientId(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClientRequest.prototype.hasClientId = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional google.protobuf.Timestamp timestamp = 2;
 * @return {?proto.google.protobuf.Timestamp}
 */
proto.ClientRequest.prototype.getTimestamp = function() {
  return /** @type{?proto.google.protobuf.Timestamp} */ (
    jspb.Message.getWrapperField(this, google_protobuf_timestamp_pb.Timestamp, 2));
};


/**
 * @param {?proto.google.protobuf.Timestamp|undefined} value
 * @return {!proto.ClientRequest} returns this
*/
proto.ClientRequest.prototype.setTimestamp = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClientRequest} returns this
 */
proto.ClientRequest.prototype.clearTimestamp = function() {
  return this.setTimestamp(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClientRequest.prototype.hasTimestamp = function() {
  return jspb.Message.getField(this, 2) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Tenant.prototype.toObject = function(opt_includeInstance) {
  return proto.Tenant.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Tenant} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Tenant.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    provider: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Tenant}
 */
proto.Tenant.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Tenant;
  return proto.Tenant.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Tenant} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Tenant}
 */
proto.Tenant.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setProvider(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Tenant.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Tenant.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Tenant} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Tenant.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getProvider();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.Tenant.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Tenant} returns this
 */
proto.Tenant.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string provider = 2;
 * @return {string}
 */
proto.Tenant.prototype.getProvider = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Tenant} returns this
 */
proto.Tenant.prototype.setProvider = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.TenantList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantList.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantList.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantsList: jspb.Message.toObjectList(msg.getTenantsList(),
    proto.Tenant.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantList}
 */
proto.TenantList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantList;
  return proto.TenantList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantList}
 */
proto.TenantList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Tenant;
      reader.readMessage(value,proto.Tenant.deserializeBinaryFromReader);
      msg.addTenants(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Tenant.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Tenant tenants = 1;
 * @return {!Array<!proto.Tenant>}
 */
proto.TenantList.prototype.getTenantsList = function() {
  return /** @type{!Array<!proto.Tenant>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Tenant, 1));
};


/**
 * @param {!Array<!proto.Tenant>} value
 * @return {!proto.TenantList} returns this
*/
proto.TenantList.prototype.setTenantsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Tenant=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Tenant}
 */
proto.TenantList.prototype.addTenants = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Tenant, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.TenantList} returns this
 */
proto.TenantList.prototype.clearTenantsList = function() {
  return this.setTenantsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantName.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantName.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantName} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantName.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    bucketName: jspb.Message.getFieldWithDefault(msg, 2, ""),
    provider: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantName}
 */
proto.TenantName.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantName;
  return proto.TenantName.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantName} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantName}
 */
proto.TenantName.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setBucketName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setProvider(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantName.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantName.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantName} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantName.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getBucketName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getProvider();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantName.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantName} returns this
 */
proto.TenantName.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string bucket_name = 2;
 * @return {string}
 */
proto.TenantName.prototype.getBucketName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantName} returns this
 */
proto.TenantName.prototype.setBucketName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string provider = 3;
 * @return {string}
 */
proto.TenantName.prototype.getProvider = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantName} returns this
 */
proto.TenantName.prototype.setProvider = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantCleanupRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantCleanupRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantCleanupRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantCleanupRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantCleanupRequest}
 */
proto.TenantCleanupRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantCleanupRequest;
  return proto.TenantCleanupRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantCleanupRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantCleanupRequest}
 */
proto.TenantCleanupRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantCleanupRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantCleanupRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantCleanupRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantCleanupRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantCleanupRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCleanupRequest} returns this
 */
proto.TenantCleanupRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.TenantCleanupRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TenantCleanupRequest} returns this
 */
proto.TenantCleanupRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantUpgradeRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantUpgradeRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantUpgradeRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantUpgradeRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    dryRun: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantUpgradeRequest}
 */
proto.TenantUpgradeRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantUpgradeRequest;
  return proto.TenantUpgradeRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantUpgradeRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantUpgradeRequest}
 */
proto.TenantUpgradeRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDryRun(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantUpgradeRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantUpgradeRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantUpgradeRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantUpgradeRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getDryRun();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantUpgradeRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantUpgradeRequest} returns this
 */
proto.TenantUpgradeRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.TenantUpgradeRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TenantUpgradeRequest} returns this
 */
proto.TenantUpgradeRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * optional bool dry_run = 3;
 * @return {boolean}
 */
proto.TenantUpgradeRequest.prototype.getDryRun = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TenantUpgradeRequest} returns this
 */
proto.TenantUpgradeRequest.prototype.setDryRun = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.TenantScanRequest.repeatedFields_ = [3];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantScanRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantScanRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantScanRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantScanRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    dryRun: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    templatesList: (f = jspb.Message.getRepeatedField(msg, 3)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantScanRequest}
 */
proto.TenantScanRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantScanRequest;
  return proto.TenantScanRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantScanRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantScanRequest}
 */
proto.TenantScanRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDryRun(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.addTemplates(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantScanRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantScanRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantScanRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantScanRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getDryRun();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getTemplatesList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      3,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantScanRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantScanRequest} returns this
 */
proto.TenantScanRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bool dry_run = 2;
 * @return {boolean}
 */
proto.TenantScanRequest.prototype.getDryRun = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TenantScanRequest} returns this
 */
proto.TenantScanRequest.prototype.setDryRun = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * repeated string templates = 3;
 * @return {!Array<string>}
 */
proto.TenantScanRequest.prototype.getTemplatesList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 3));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.TenantScanRequest} returns this
 */
proto.TenantScanRequest.prototype.setTemplatesList = function(value) {
  return jspb.Message.setField(this, 3, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.TenantScanRequest} returns this
 */
proto.TenantScanRequest.prototype.addTemplates = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 3, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.TenantScanRequest} returns this
 */
proto.TenantScanRequest.prototype.clearTemplatesList = function() {
  return this.setTemplatesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ScanResult.prototype.toObject = function(opt_includeInstance) {
  return proto.ScanResult.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ScanResult} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScanResult.toObject = function(includeInstance, msg) {
  var f, obj = {
    templateName: jspb.Message.getFieldWithDefault(msg, 1, ""),
    scanSuccess: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ScanResult}
 */
proto.ScanResult.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ScanResult;
  return proto.ScanResult.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ScanResult} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ScanResult}
 */
proto.ScanResult.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTemplateName(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setScanSuccess(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ScanResult.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ScanResult.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ScanResult} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScanResult.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTemplateName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getScanSuccess();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional string template_name = 1;
 * @return {string}
 */
proto.ScanResult.prototype.getTemplateName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScanResult} returns this
 */
proto.ScanResult.prototype.setTemplateName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bool scan_success = 2;
 * @return {boolean}
 */
proto.ScanResult.prototype.getScanSuccess = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ScanResult} returns this
 */
proto.ScanResult.prototype.setScanSuccess = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ScanResultList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ScanResultList.prototype.toObject = function(opt_includeInstance) {
  return proto.ScanResultList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ScanResultList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScanResultList.toObject = function(includeInstance, msg) {
  var f, obj = {
    resultsList: jspb.Message.toObjectList(msg.getResultsList(),
    proto.ScanResult.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ScanResultList}
 */
proto.ScanResultList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ScanResultList;
  return proto.ScanResultList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ScanResultList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ScanResultList}
 */
proto.ScanResultList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ScanResult;
      reader.readMessage(value,proto.ScanResult.deserializeBinaryFromReader);
      msg.addResults(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ScanResultList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ScanResultList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ScanResultList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScanResultList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getResultsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.ScanResult.serializeBinaryToWriter
    );
  }
};


/**
 * repeated ScanResult results = 1;
 * @return {!Array<!proto.ScanResult>}
 */
proto.ScanResultList.prototype.getResultsList = function() {
  return /** @type{!Array<!proto.ScanResult>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.ScanResult, 1));
};


/**
 * @param {!Array<!proto.ScanResult>} value
 * @return {!proto.ScanResultList} returns this
*/
proto.ScanResultList.prototype.setResultsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.ScanResult=} opt_value
 * @param {number=} opt_index
 * @return {!proto.ScanResult}
 */
proto.ScanResultList.prototype.addResults = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.ScanResult, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ScanResultList} returns this
 */
proto.ScanResultList.prototype.clearResultsList = function() {
  return this.setResultsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantInspectRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantInspectRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantInspectRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantInspectRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    userId: jspb.Message.getFieldWithDefault(msg, 2, ""),
    groupId: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantInspectRequest}
 */
proto.TenantInspectRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantInspectRequest;
  return proto.TenantInspectRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantInspectRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantInspectRequest}
 */
proto.TenantInspectRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setUserId(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setGroupId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantInspectRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantInspectRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantInspectRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantInspectRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getUserId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getGroupId();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantInspectRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantInspectRequest} returns this
 */
proto.TenantInspectRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string user_id = 2;
 * @return {string}
 */
proto.TenantInspectRequest.prototype.getUserId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantInspectRequest} returns this
 */
proto.TenantInspectRequest.prototype.setUserId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string group_id = 3;
 * @return {string}
 */
proto.TenantInspectRequest.prototype.getGroupId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantInspectRequest} returns this
 */
proto.TenantInspectRequest.prototype.setGroupId = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.KeyValue.prototype.toObject = function(opt_includeInstance) {
  return proto.KeyValue.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.KeyValue} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.KeyValue.toObject = function(includeInstance, msg) {
  var f, obj = {
    key: jspb.Message.getFieldWithDefault(msg, 1, ""),
    value: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.KeyValue}
 */
proto.KeyValue.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.KeyValue;
  return proto.KeyValue.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.KeyValue} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.KeyValue}
 */
proto.KeyValue.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setKey(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.KeyValue.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.KeyValue.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.KeyValue} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.KeyValue.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getKey();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getValue();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional string key = 1;
 * @return {string}
 */
proto.KeyValue.prototype.getKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.KeyValue} returns this
 */
proto.KeyValue.prototype.setKey = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string value = 2;
 * @return {string}
 */
proto.KeyValue.prototype.getValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.KeyValue} returns this
 */
proto.KeyValue.prototype.setValue = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantIdentity.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantIdentity.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantIdentity} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantIdentity.toObject = function(includeInstance, msg) {
  var f, obj = {
    user: (f = msg.getUser()) && proto.KeyValue.toObject(includeInstance, f),
    appKey: (f = msg.getAppKey()) && proto.KeyValue.toObject(includeInstance, f),
    domain: (f = msg.getDomain()) && proto.KeyValue.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantIdentity}
 */
proto.TenantIdentity.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantIdentity;
  return proto.TenantIdentity.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantIdentity} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantIdentity}
 */
proto.TenantIdentity.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.KeyValue;
      reader.readMessage(value,proto.KeyValue.deserializeBinaryFromReader);
      msg.setUser(value);
      break;
    case 2:
      var value = new proto.KeyValue;
      reader.readMessage(value,proto.KeyValue.deserializeBinaryFromReader);
      msg.setAppKey(value);
      break;
    case 3:
      var value = new proto.KeyValue;
      reader.readMessage(value,proto.KeyValue.deserializeBinaryFromReader);
      msg.setDomain(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantIdentity.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantIdentity.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantIdentity} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantIdentity.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getUser();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.KeyValue.serializeBinaryToWriter
    );
  }
  f = message.getAppKey();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.KeyValue.serializeBinaryToWriter
    );
  }
  f = message.getDomain();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.KeyValue.serializeBinaryToWriter
    );
  }
};


/**
 * optional KeyValue user = 1;
 * @return {?proto.KeyValue}
 */
proto.TenantIdentity.prototype.getUser = function() {
  return /** @type{?proto.KeyValue} */ (
    jspb.Message.getWrapperField(this, proto.KeyValue, 1));
};


/**
 * @param {?proto.KeyValue|undefined} value
 * @return {!proto.TenantIdentity} returns this
*/
proto.TenantIdentity.prototype.setUser = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantIdentity} returns this
 */
proto.TenantIdentity.prototype.clearUser = function() {
  return this.setUser(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantIdentity.prototype.hasUser = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional KeyValue app_key = 2;
 * @return {?proto.KeyValue}
 */
proto.TenantIdentity.prototype.getAppKey = function() {
  return /** @type{?proto.KeyValue} */ (
    jspb.Message.getWrapperField(this, proto.KeyValue, 2));
};


/**
 * @param {?proto.KeyValue|undefined} value
 * @return {!proto.TenantIdentity} returns this
*/
proto.TenantIdentity.prototype.setAppKey = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantIdentity} returns this
 */
proto.TenantIdentity.prototype.clearAppKey = function() {
  return this.setAppKey(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantIdentity.prototype.hasAppKey = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional KeyValue domain = 3;
 * @return {?proto.KeyValue}
 */
proto.TenantIdentity.prototype.getDomain = function() {
  return /** @type{?proto.KeyValue} */ (
    jspb.Message.getWrapperField(this, proto.KeyValue, 3));
};


/**
 * @param {?proto.KeyValue|undefined} value
 * @return {!proto.TenantIdentity} returns this
*/
proto.TenantIdentity.prototype.setDomain = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantIdentity} returns this
 */
proto.TenantIdentity.prototype.clearDomain = function() {
  return this.setDomain(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantIdentity.prototype.hasDomain = function() {
  return jspb.Message.getField(this, 3) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.TenantCompute.repeatedFields_ = [9];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantCompute.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantCompute.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantCompute} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantCompute.toObject = function(includeInstance, msg) {
  var f, obj = {
    region: jspb.Message.getFieldWithDefault(msg, 1, ""),
    subRegion: jspb.Message.getFieldWithDefault(msg, 2, ""),
    availabilityZone: jspb.Message.getFieldWithDefault(msg, 3, ""),
    context: (f = msg.getContext()) && proto.KeyValue.toObject(includeInstance, f),
    apiKey: (f = msg.getApiKey()) && proto.KeyValue.toObject(includeInstance, f),
    whitelistTemplateRegex: jspb.Message.getFieldWithDefault(msg, 6, ""),
    blacklistTemplateRegex: jspb.Message.getFieldWithDefault(msg, 7, ""),
    defaultImage: jspb.Message.getFieldWithDefault(msg, 8, ""),
    dnsListList: (f = jspb.Message.getRepeatedField(msg, 9)) == null ? undefined : f,
    operatorUsername: jspb.Message.getFieldWithDefault(msg, 10, ""),
    whitelistImageRegex: jspb.Message.getFieldWithDefault(msg, 11, ""),
    blacklistImageRegex: jspb.Message.getFieldWithDefault(msg, 12, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantCompute}
 */
proto.TenantCompute.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantCompute;
  return proto.TenantCompute.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantCompute} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantCompute}
 */
proto.TenantCompute.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setRegion(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setSubRegion(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setAvailabilityZone(value);
      break;
    case 4:
      var value = new proto.KeyValue;
      reader.readMessage(value,proto.KeyValue.deserializeBinaryFromReader);
      msg.setContext(value);
      break;
    case 5:
      var value = new proto.KeyValue;
      reader.readMessage(value,proto.KeyValue.deserializeBinaryFromReader);
      msg.setApiKey(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setWhitelistTemplateRegex(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setBlacklistTemplateRegex(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setDefaultImage(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.addDnsList(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.setOperatorUsername(value);
      break;
    case 11:
      var value = /** @type {string} */ (reader.readString());
      msg.setWhitelistImageRegex(value);
      break;
    case 12:
      var value = /** @type {string} */ (reader.readString());
      msg.setBlacklistImageRegex(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantCompute.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantCompute.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantCompute} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantCompute.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getRegion();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getSubRegion();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getAvailabilityZone();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getContext();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.KeyValue.serializeBinaryToWriter
    );
  }
  f = message.getApiKey();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.KeyValue.serializeBinaryToWriter
    );
  }
  f = message.getWhitelistTemplateRegex();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getBlacklistTemplateRegex();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getDefaultImage();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getDnsListList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      9,
      f
    );
  }
  f = message.getOperatorUsername();
  if (f.length > 0) {
    writer.writeString(
      10,
      f
    );
  }
  f = message.getWhitelistImageRegex();
  if (f.length > 0) {
    writer.writeString(
      11,
      f
    );
  }
  f = message.getBlacklistImageRegex();
  if (f.length > 0) {
    writer.writeString(
      12,
      f
    );
  }
};


/**
 * optional string region = 1;
 * @return {string}
 */
proto.TenantCompute.prototype.getRegion = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setRegion = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string sub_region = 2;
 * @return {string}
 */
proto.TenantCompute.prototype.getSubRegion = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setSubRegion = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string availability_zone = 3;
 * @return {string}
 */
proto.TenantCompute.prototype.getAvailabilityZone = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setAvailabilityZone = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional KeyValue context = 4;
 * @return {?proto.KeyValue}
 */
proto.TenantCompute.prototype.getContext = function() {
  return /** @type{?proto.KeyValue} */ (
    jspb.Message.getWrapperField(this, proto.KeyValue, 4));
};


/**
 * @param {?proto.KeyValue|undefined} value
 * @return {!proto.TenantCompute} returns this
*/
proto.TenantCompute.prototype.setContext = function(value) {
  return jspb.Message.setWrapperField(this, 4, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.clearContext = function() {
  return this.setContext(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantCompute.prototype.hasContext = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * optional KeyValue api_key = 5;
 * @return {?proto.KeyValue}
 */
proto.TenantCompute.prototype.getApiKey = function() {
  return /** @type{?proto.KeyValue} */ (
    jspb.Message.getWrapperField(this, proto.KeyValue, 5));
};


/**
 * @param {?proto.KeyValue|undefined} value
 * @return {!proto.TenantCompute} returns this
*/
proto.TenantCompute.prototype.setApiKey = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.clearApiKey = function() {
  return this.setApiKey(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantCompute.prototype.hasApiKey = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional string whitelist_template_regex = 6;
 * @return {string}
 */
proto.TenantCompute.prototype.getWhitelistTemplateRegex = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setWhitelistTemplateRegex = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string blacklist_template_regex = 7;
 * @return {string}
 */
proto.TenantCompute.prototype.getBlacklistTemplateRegex = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setBlacklistTemplateRegex = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string default_image = 8;
 * @return {string}
 */
proto.TenantCompute.prototype.getDefaultImage = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setDefaultImage = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * repeated string dns_list = 9;
 * @return {!Array<string>}
 */
proto.TenantCompute.prototype.getDnsListList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 9));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setDnsListList = function(value) {
  return jspb.Message.setField(this, 9, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.addDnsList = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 9, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.clearDnsListList = function() {
  return this.setDnsListList([]);
};


/**
 * optional string operator_username = 10;
 * @return {string}
 */
proto.TenantCompute.prototype.getOperatorUsername = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 10, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setOperatorUsername = function(value) {
  return jspb.Message.setProto3StringField(this, 10, value);
};


/**
 * optional string whitelist_image_regex = 11;
 * @return {string}
 */
proto.TenantCompute.prototype.getWhitelistImageRegex = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 11, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setWhitelistImageRegex = function(value) {
  return jspb.Message.setProto3StringField(this, 11, value);
};


/**
 * optional string blacklist_image_regex = 12;
 * @return {string}
 */
proto.TenantCompute.prototype.getBlacklistImageRegex = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 12, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantCompute} returns this
 */
proto.TenantCompute.prototype.setBlacklistImageRegex = function(value) {
  return jspb.Message.setProto3StringField(this, 12, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantNetwork.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantNetwork.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantNetwork} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantNetwork.toObject = function(includeInstance, msg) {
  var f, obj = {
    vpcName: jspb.Message.getFieldWithDefault(msg, 1, ""),
    vpcIdr: jspb.Message.getFieldWithDefault(msg, 2, ""),
    providerNetwork: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantNetwork}
 */
proto.TenantNetwork.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantNetwork;
  return proto.TenantNetwork.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantNetwork} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantNetwork}
 */
proto.TenantNetwork.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setVpcName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setVpcIdr(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setProviderNetwork(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantNetwork.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantNetwork.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantNetwork} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantNetwork.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getVpcName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getVpcIdr();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getProviderNetwork();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string vpc_name = 1;
 * @return {string}
 */
proto.TenantNetwork.prototype.getVpcName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantNetwork} returns this
 */
proto.TenantNetwork.prototype.setVpcName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string vpc_idr = 2;
 * @return {string}
 */
proto.TenantNetwork.prototype.getVpcIdr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantNetwork} returns this
 */
proto.TenantNetwork.prototype.setVpcIdr = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string provider_network = 3;
 * @return {string}
 */
proto.TenantNetwork.prototype.getProviderNetwork = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantNetwork} returns this
 */
proto.TenantNetwork.prototype.setProviderNetwork = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantObjectStorage.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantObjectStorage.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantObjectStorage} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantObjectStorage.toObject = function(includeInstance, msg) {
  var f, obj = {
    type: jspb.Message.getFieldWithDefault(msg, 1, ""),
    endpoint: jspb.Message.getFieldWithDefault(msg, 2, ""),
    authUrl: jspb.Message.getFieldWithDefault(msg, 3, ""),
    accessKey: jspb.Message.getFieldWithDefault(msg, 4, ""),
    region: jspb.Message.getFieldWithDefault(msg, 5, ""),
    projectName: jspb.Message.getFieldWithDefault(msg, 6, ""),
    applicationKey: jspb.Message.getFieldWithDefault(msg, 7, ""),
    username: jspb.Message.getFieldWithDefault(msg, 8, ""),
    password: jspb.Message.getFieldWithDefault(msg, 9, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantObjectStorage}
 */
proto.TenantObjectStorage.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantObjectStorage;
  return proto.TenantObjectStorage.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantObjectStorage} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantObjectStorage}
 */
proto.TenantObjectStorage.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setType(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setEndpoint(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setAuthUrl(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setAccessKey(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setRegion(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setProjectName(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setApplicationKey(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setUsername(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.setPassword(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantObjectStorage.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantObjectStorage.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantObjectStorage} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantObjectStorage.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getType();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getEndpoint();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getAuthUrl();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getAccessKey();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getRegion();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getProjectName();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getApplicationKey();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getUsername();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getPassword();
  if (f.length > 0) {
    writer.writeString(
      9,
      f
    );
  }
};


/**
 * optional string type = 1;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setType = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string endpoint = 2;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getEndpoint = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setEndpoint = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string auth_url = 3;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getAuthUrl = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setAuthUrl = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string access_key = 4;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getAccessKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setAccessKey = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string region = 5;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getRegion = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setRegion = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string project_name = 6;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getProjectName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setProjectName = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string application_key = 7;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getApplicationKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setApplicationKey = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string username = 8;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getUsername = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setUsername = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * optional string password = 9;
 * @return {string}
 */
proto.TenantObjectStorage.prototype.getPassword = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 9, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantObjectStorage} returns this
 */
proto.TenantObjectStorage.prototype.setPassword = function(value) {
  return jspb.Message.setProto3StringField(this, 9, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantMetadata.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantMetadata.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantMetadata} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantMetadata.toObject = function(includeInstance, msg) {
  var f, obj = {
    storage: (f = msg.getStorage()) && proto.TenantObjectStorage.toObject(includeInstance, f),
    bucketName: jspb.Message.getFieldWithDefault(msg, 2, ""),
    crypt: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantMetadata}
 */
proto.TenantMetadata.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantMetadata;
  return proto.TenantMetadata.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantMetadata} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantMetadata}
 */
proto.TenantMetadata.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.TenantObjectStorage;
      reader.readMessage(value,proto.TenantObjectStorage.deserializeBinaryFromReader);
      msg.setStorage(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setBucketName(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setCrypt(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantMetadata.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantMetadata.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantMetadata} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantMetadata.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getStorage();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.TenantObjectStorage.serializeBinaryToWriter
    );
  }
  f = message.getBucketName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCrypt();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional TenantObjectStorage storage = 1;
 * @return {?proto.TenantObjectStorage}
 */
proto.TenantMetadata.prototype.getStorage = function() {
  return /** @type{?proto.TenantObjectStorage} */ (
    jspb.Message.getWrapperField(this, proto.TenantObjectStorage, 1));
};


/**
 * @param {?proto.TenantObjectStorage|undefined} value
 * @return {!proto.TenantMetadata} returns this
*/
proto.TenantMetadata.prototype.setStorage = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantMetadata} returns this
 */
proto.TenantMetadata.prototype.clearStorage = function() {
  return this.setStorage(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantMetadata.prototype.hasStorage = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string bucket_name = 2;
 * @return {string}
 */
proto.TenantMetadata.prototype.getBucketName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantMetadata} returns this
 */
proto.TenantMetadata.prototype.setBucketName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional bool crypt = 3;
 * @return {boolean}
 */
proto.TenantMetadata.prototype.getCrypt = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TenantMetadata} returns this
 */
proto.TenantMetadata.prototype.setCrypt = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantInspectResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantInspectResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantInspectResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantInspectResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    provider: jspb.Message.getFieldWithDefault(msg, 2, ""),
    identity: (f = msg.getIdentity()) && proto.TenantIdentity.toObject(includeInstance, f),
    compute: (f = msg.getCompute()) && proto.TenantCompute.toObject(includeInstance, f),
    objectStorage: (f = msg.getObjectStorage()) && proto.TenantObjectStorage.toObject(includeInstance, f),
    metadata: (f = msg.getMetadata()) && proto.TenantMetadata.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantInspectResponse}
 */
proto.TenantInspectResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantInspectResponse;
  return proto.TenantInspectResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantInspectResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantInspectResponse}
 */
proto.TenantInspectResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setProvider(value);
      break;
    case 3:
      var value = new proto.TenantIdentity;
      reader.readMessage(value,proto.TenantIdentity.deserializeBinaryFromReader);
      msg.setIdentity(value);
      break;
    case 4:
      var value = new proto.TenantCompute;
      reader.readMessage(value,proto.TenantCompute.deserializeBinaryFromReader);
      msg.setCompute(value);
      break;
    case 5:
      var value = new proto.TenantObjectStorage;
      reader.readMessage(value,proto.TenantObjectStorage.deserializeBinaryFromReader);
      msg.setObjectStorage(value);
      break;
    case 6:
      var value = new proto.TenantMetadata;
      reader.readMessage(value,proto.TenantMetadata.deserializeBinaryFromReader);
      msg.setMetadata(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantInspectResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantInspectResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantInspectResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantInspectResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getProvider();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getIdentity();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.TenantIdentity.serializeBinaryToWriter
    );
  }
  f = message.getCompute();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.TenantCompute.serializeBinaryToWriter
    );
  }
  f = message.getObjectStorage();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.TenantObjectStorage.serializeBinaryToWriter
    );
  }
  f = message.getMetadata();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.TenantMetadata.serializeBinaryToWriter
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.TenantInspectResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string provider = 2;
 * @return {string}
 */
proto.TenantInspectResponse.prototype.getProvider = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.setProvider = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional TenantIdentity identity = 3;
 * @return {?proto.TenantIdentity}
 */
proto.TenantInspectResponse.prototype.getIdentity = function() {
  return /** @type{?proto.TenantIdentity} */ (
    jspb.Message.getWrapperField(this, proto.TenantIdentity, 3));
};


/**
 * @param {?proto.TenantIdentity|undefined} value
 * @return {!proto.TenantInspectResponse} returns this
*/
proto.TenantInspectResponse.prototype.setIdentity = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.clearIdentity = function() {
  return this.setIdentity(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantInspectResponse.prototype.hasIdentity = function() {
  return jspb.Message.getField(this, 3) != null;
};


/**
 * optional TenantCompute compute = 4;
 * @return {?proto.TenantCompute}
 */
proto.TenantInspectResponse.prototype.getCompute = function() {
  return /** @type{?proto.TenantCompute} */ (
    jspb.Message.getWrapperField(this, proto.TenantCompute, 4));
};


/**
 * @param {?proto.TenantCompute|undefined} value
 * @return {!proto.TenantInspectResponse} returns this
*/
proto.TenantInspectResponse.prototype.setCompute = function(value) {
  return jspb.Message.setWrapperField(this, 4, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.clearCompute = function() {
  return this.setCompute(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantInspectResponse.prototype.hasCompute = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * optional TenantObjectStorage object_storage = 5;
 * @return {?proto.TenantObjectStorage}
 */
proto.TenantInspectResponse.prototype.getObjectStorage = function() {
  return /** @type{?proto.TenantObjectStorage} */ (
    jspb.Message.getWrapperField(this, proto.TenantObjectStorage, 5));
};


/**
 * @param {?proto.TenantObjectStorage|undefined} value
 * @return {!proto.TenantInspectResponse} returns this
*/
proto.TenantInspectResponse.prototype.setObjectStorage = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.clearObjectStorage = function() {
  return this.setObjectStorage(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantInspectResponse.prototype.hasObjectStorage = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional TenantMetadata metadata = 6;
 * @return {?proto.TenantMetadata}
 */
proto.TenantInspectResponse.prototype.getMetadata = function() {
  return /** @type{?proto.TenantMetadata} */ (
    jspb.Message.getWrapperField(this, proto.TenantMetadata, 6));
};


/**
 * @param {?proto.TenantMetadata|undefined} value
 * @return {!proto.TenantInspectResponse} returns this
*/
proto.TenantInspectResponse.prototype.setMetadata = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TenantInspectResponse} returns this
 */
proto.TenantInspectResponse.prototype.clearMetadata = function() {
  return this.setMetadata(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TenantInspectResponse.prototype.hasMetadata = function() {
  return jspb.Message.getField(this, 6) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.TenantUpgradeResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TenantUpgradeResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.TenantUpgradeResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TenantUpgradeResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantUpgradeResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    actionsList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TenantUpgradeResponse}
 */
proto.TenantUpgradeResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TenantUpgradeResponse;
  return proto.TenantUpgradeResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TenantUpgradeResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TenantUpgradeResponse}
 */
proto.TenantUpgradeResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addActions(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TenantUpgradeResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TenantUpgradeResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TenantUpgradeResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TenantUpgradeResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getActionsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
};


/**
 * repeated string actions = 1;
 * @return {!Array<string>}
 */
proto.TenantUpgradeResponse.prototype.getActionsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.TenantUpgradeResponse} returns this
 */
proto.TenantUpgradeResponse.prototype.setActionsList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.TenantUpgradeResponse} returns this
 */
proto.TenantUpgradeResponse.prototype.addActions = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.TenantUpgradeResponse} returns this
 */
proto.TenantUpgradeResponse.prototype.clearActionsList = function() {
  return this.setActionsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Image.prototype.toObject = function(opt_includeInstance) {
  return proto.Image.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Image} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Image.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Image}
 */
proto.Image.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Image;
  return proto.Image.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Image} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Image}
 */
proto.Image.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Image.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Image.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Image} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Image.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.Image.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Image} returns this
 */
proto.Image.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.Image.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Image} returns this
 */
proto.Image.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ImageList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ImageList.prototype.toObject = function(opt_includeInstance) {
  return proto.ImageList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ImageList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ImageList.toObject = function(includeInstance, msg) {
  var f, obj = {
    imagesList: jspb.Message.toObjectList(msg.getImagesList(),
    proto.Image.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ImageList}
 */
proto.ImageList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ImageList;
  return proto.ImageList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ImageList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ImageList}
 */
proto.ImageList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Image;
      reader.readMessage(value,proto.Image.deserializeBinaryFromReader);
      msg.addImages(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ImageList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ImageList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ImageList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ImageList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getImagesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Image.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Image images = 1;
 * @return {!Array<!proto.Image>}
 */
proto.ImageList.prototype.getImagesList = function() {
  return /** @type{!Array<!proto.Image>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Image, 1));
};


/**
 * @param {!Array<!proto.Image>} value
 * @return {!proto.ImageList} returns this
*/
proto.ImageList.prototype.setImagesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Image=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Image}
 */
proto.ImageList.prototype.addImages = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Image, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ImageList} returns this
 */
proto.ImageList.prototype.clearImagesList = function() {
  return this.setImagesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ImageListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ImageListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ImageListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ImageListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ImageListRequest}
 */
proto.ImageListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ImageListRequest;
  return proto.ImageListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ImageListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ImageListRequest}
 */
proto.ImageListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ImageListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ImageListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ImageListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ImageListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.ImageListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ImageListRequest} returns this
 */
proto.ImageListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.ImageListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ImageListRequest} returns this
 */
proto.ImageListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.NetworkCreateRequest.repeatedFields_ = [9];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.NetworkCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.NetworkCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.NetworkCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cidr: jspb.Message.getFieldWithDefault(msg, 3, ""),
    gateway: (f = msg.getGateway()) && proto.GatewayDefinition.toObject(includeInstance, f),
    failOver: jspb.Message.getBooleanFieldWithDefault(msg, 5, false),
    domain: jspb.Message.getFieldWithDefault(msg, 6, ""),
    keepOnFailure: jspb.Message.getBooleanFieldWithDefault(msg, 7, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 8, ""),
    dnsServersList: (f = jspb.Message.getRepeatedField(msg, 9)) == null ? undefined : f,
    noSubnet: jspb.Message.getBooleanFieldWithDefault(msg, 10, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.NetworkCreateRequest}
 */
proto.NetworkCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.NetworkCreateRequest;
  return proto.NetworkCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.NetworkCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.NetworkCreateRequest}
 */
proto.NetworkCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 4:
      var value = new proto.GatewayDefinition;
      reader.readMessage(value,proto.GatewayDefinition.deserializeBinaryFromReader);
      msg.setGateway(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setFailOver(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setDomain(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setKeepOnFailure(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.addDnsServers(value);
      break;
    case 10:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setNoSubnet(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.NetworkCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.NetworkCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.NetworkCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getGateway();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.GatewayDefinition.serializeBinaryToWriter
    );
  }
  f = message.getFailOver();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
  f = message.getDomain();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getKeepOnFailure();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getDnsServersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      9,
      f
    );
  }
  f = message.getNoSubnet();
  if (f) {
    writer.writeBool(
      10,
      f
    );
  }
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.NetworkCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string cidr = 3;
 * @return {string}
 */
proto.NetworkCreateRequest.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional GatewayDefinition gateway = 4;
 * @return {?proto.GatewayDefinition}
 */
proto.NetworkCreateRequest.prototype.getGateway = function() {
  return /** @type{?proto.GatewayDefinition} */ (
    jspb.Message.getWrapperField(this, proto.GatewayDefinition, 4));
};


/**
 * @param {?proto.GatewayDefinition|undefined} value
 * @return {!proto.NetworkCreateRequest} returns this
*/
proto.NetworkCreateRequest.prototype.setGateway = function(value) {
  return jspb.Message.setWrapperField(this, 4, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.clearGateway = function() {
  return this.setGateway(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.NetworkCreateRequest.prototype.hasGateway = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * optional bool fail_over = 5;
 * @return {boolean}
 */
proto.NetworkCreateRequest.prototype.getFailOver = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setFailOver = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};


/**
 * optional string domain = 6;
 * @return {string}
 */
proto.NetworkCreateRequest.prototype.getDomain = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setDomain = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional bool keep_on_failure = 7;
 * @return {boolean}
 */
proto.NetworkCreateRequest.prototype.getKeepOnFailure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setKeepOnFailure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};


/**
 * optional string tenant_id = 8;
 * @return {string}
 */
proto.NetworkCreateRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * repeated string dns_servers = 9;
 * @return {!Array<string>}
 */
proto.NetworkCreateRequest.prototype.getDnsServersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 9));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setDnsServersList = function(value) {
  return jspb.Message.setField(this, 9, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.addDnsServers = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 9, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.clearDnsServersList = function() {
  return this.setDnsServersList([]);
};


/**
 * optional bool no_subnet = 10;
 * @return {boolean}
 */
proto.NetworkCreateRequest.prototype.getNoSubnet = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 10, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NetworkCreateRequest} returns this
 */
proto.NetworkCreateRequest.prototype.setNoSubnet = function(value) {
  return jspb.Message.setProto3BooleanField(this, 10, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.Network.repeatedFields_ = [9,10];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Network.prototype.toObject = function(opt_includeInstance) {
  return proto.Network.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Network} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Network.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cidr: jspb.Message.getFieldWithDefault(msg, 3, ""),
    gatewayId: jspb.Message.getFieldWithDefault(msg, 4, ""),
    secondaryGatewayId: jspb.Message.getFieldWithDefault(msg, 5, ""),
    virtualIp: (f = msg.getVirtualIp()) && proto.VirtualIp.toObject(includeInstance, f),
    failover: jspb.Message.getBooleanFieldWithDefault(msg, 7, false),
    state: jspb.Message.getFieldWithDefault(msg, 8, 0),
    subnetsList: (f = jspb.Message.getRepeatedField(msg, 9)) == null ? undefined : f,
    dnsServersList: (f = jspb.Message.getRepeatedField(msg, 10)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Network}
 */
proto.Network.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Network;
  return proto.Network.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Network} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Network}
 */
proto.Network.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewayId(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setSecondaryGatewayId(value);
      break;
    case 6:
      var value = new proto.VirtualIp;
      reader.readMessage(value,proto.VirtualIp.deserializeBinaryFromReader);
      msg.setVirtualIp(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setFailover(value);
      break;
    case 8:
      var value = /** @type {!proto.NetworkState} */ (reader.readEnum());
      msg.setState(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.addSubnets(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.addDnsServers(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Network.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Network.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Network} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Network.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getGatewayId();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getSecondaryGatewayId();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getVirtualIp();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.VirtualIp.serializeBinaryToWriter
    );
  }
  f = message.getFailover();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      8,
      f
    );
  }
  f = message.getSubnetsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      9,
      f
    );
  }
  f = message.getDnsServersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      10,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.Network.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.Network.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string cidr = 3;
 * @return {string}
 */
proto.Network.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string gateway_id = 4;
 * @return {string}
 */
proto.Network.prototype.getGatewayId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setGatewayId = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string secondary_gateway_id = 5;
 * @return {string}
 */
proto.Network.prototype.getSecondaryGatewayId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setSecondaryGatewayId = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional VirtualIp virtual_ip = 6;
 * @return {?proto.VirtualIp}
 */
proto.Network.prototype.getVirtualIp = function() {
  return /** @type{?proto.VirtualIp} */ (
    jspb.Message.getWrapperField(this, proto.VirtualIp, 6));
};


/**
 * @param {?proto.VirtualIp|undefined} value
 * @return {!proto.Network} returns this
*/
proto.Network.prototype.setVirtualIp = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.clearVirtualIp = function() {
  return this.setVirtualIp(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.Network.prototype.hasVirtualIp = function() {
  return jspb.Message.getField(this, 6) != null;
};


/**
 * optional bool failover = 7;
 * @return {boolean}
 */
proto.Network.prototype.getFailover = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setFailover = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};


/**
 * optional NetworkState state = 8;
 * @return {!proto.NetworkState}
 */
proto.Network.prototype.getState = function() {
  return /** @type {!proto.NetworkState} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {!proto.NetworkState} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 8, value);
};


/**
 * repeated string subnets = 9;
 * @return {!Array<string>}
 */
proto.Network.prototype.getSubnetsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 9));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setSubnetsList = function(value) {
  return jspb.Message.setField(this, 9, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.addSubnets = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 9, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.clearSubnetsList = function() {
  return this.setSubnetsList([]);
};


/**
 * repeated string dns_servers = 10;
 * @return {!Array<string>}
 */
proto.Network.prototype.getDnsServersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 10));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.setDnsServersList = function(value) {
  return jspb.Message.setField(this, 10, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.addDnsServers = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 10, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.Network} returns this
 */
proto.Network.prototype.clearDnsServersList = function() {
  return this.setDnsServersList([]);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.NetworkList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.NetworkList.prototype.toObject = function(opt_includeInstance) {
  return proto.NetworkList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.NetworkList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkList.toObject = function(includeInstance, msg) {
  var f, obj = {
    networksList: jspb.Message.toObjectList(msg.getNetworksList(),
    proto.Network.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.NetworkList}
 */
proto.NetworkList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.NetworkList;
  return proto.NetworkList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.NetworkList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.NetworkList}
 */
proto.NetworkList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Network;
      reader.readMessage(value,proto.Network.deserializeBinaryFromReader);
      msg.addNetworks(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.NetworkList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.NetworkList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.NetworkList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetworksList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Network.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Network networks = 1;
 * @return {!Array<!proto.Network>}
 */
proto.NetworkList.prototype.getNetworksList = function() {
  return /** @type{!Array<!proto.Network>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Network, 1));
};


/**
 * @param {!Array<!proto.Network>} value
 * @return {!proto.NetworkList} returns this
*/
proto.NetworkList.prototype.setNetworksList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Network=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Network}
 */
proto.NetworkList.prototype.addNetworks = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Network, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.NetworkList} returns this
 */
proto.NetworkList.prototype.clearNetworksList = function() {
  return this.setNetworksList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.NetworkListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.NetworkListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.NetworkListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.NetworkListRequest}
 */
proto.NetworkListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.NetworkListRequest;
  return proto.NetworkListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.NetworkListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.NetworkListRequest}
 */
proto.NetworkListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.NetworkListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.NetworkListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.NetworkListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.NetworkListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NetworkListRequest} returns this
 */
proto.NetworkListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.NetworkListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.NetworkListRequest} returns this
 */
proto.NetworkListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.NetworkDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.NetworkDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.NetworkDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.NetworkDeleteRequest}
 */
proto.NetworkDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.NetworkDeleteRequest;
  return proto.NetworkDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.NetworkDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.NetworkDeleteRequest}
 */
proto.NetworkDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.NetworkDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.NetworkDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.NetworkDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NetworkDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.NetworkDeleteRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.NetworkDeleteRequest} returns this
*/
proto.NetworkDeleteRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.NetworkDeleteRequest} returns this
 */
proto.NetworkDeleteRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.NetworkDeleteRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.NetworkDeleteRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NetworkDeleteRequest} returns this
 */
proto.NetworkDeleteRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.VirtualIp.repeatedFields_ = [6];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VirtualIp.prototype.toObject = function(opt_includeInstance) {
  return proto.VirtualIp.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VirtualIp} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VirtualIp.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    networkId: jspb.Message.getFieldWithDefault(msg, 3, ""),
    privateIp: jspb.Message.getFieldWithDefault(msg, 4, ""),
    publicIp: jspb.Message.getFieldWithDefault(msg, 5, ""),
    hostsList: jspb.Message.toObjectList(msg.getHostsList(),
    proto.Host.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VirtualIp}
 */
proto.VirtualIp.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VirtualIp;
  return proto.VirtualIp.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VirtualIp} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VirtualIp}
 */
proto.VirtualIp.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setNetworkId(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrivateIp(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setPublicIp(value);
      break;
    case 6:
      var value = new proto.Host;
      reader.readMessage(value,proto.Host.deserializeBinaryFromReader);
      msg.addHosts(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VirtualIp.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VirtualIp.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VirtualIp} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VirtualIp.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getNetworkId();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getPrivateIp();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getPublicIp();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getHostsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      6,
      f,
      proto.Host.serializeBinaryToWriter
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.VirtualIp.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.VirtualIp.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string network_id = 3;
 * @return {string}
 */
proto.VirtualIp.prototype.getNetworkId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.setNetworkId = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string private_ip = 4;
 * @return {string}
 */
proto.VirtualIp.prototype.getPrivateIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.setPrivateIp = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string public_ip = 5;
 * @return {string}
 */
proto.VirtualIp.prototype.getPublicIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.setPublicIp = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * repeated Host hosts = 6;
 * @return {!Array<!proto.Host>}
 */
proto.VirtualIp.prototype.getHostsList = function() {
  return /** @type{!Array<!proto.Host>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Host, 6));
};


/**
 * @param {!Array<!proto.Host>} value
 * @return {!proto.VirtualIp} returns this
*/
proto.VirtualIp.prototype.setHostsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 6, value);
};


/**
 * @param {!proto.Host=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Host}
 */
proto.VirtualIp.prototype.addHosts = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 6, opt_value, proto.Host, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.VirtualIp} returns this
 */
proto.VirtualIp.prototype.clearHostsList = function() {
  return this.setHostsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cidr: jspb.Message.getFieldWithDefault(msg, 3, ""),
    gateway: (f = msg.getGateway()) && proto.GatewayDefinition.toObject(includeInstance, f),
    failOver: jspb.Message.getBooleanFieldWithDefault(msg, 5, false),
    domain: jspb.Message.getFieldWithDefault(msg, 6, ""),
    keepOnFailure: jspb.Message.getBooleanFieldWithDefault(msg, 7, false),
    defaultSshPort: jspb.Message.getFieldWithDefault(msg, 8, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetCreateRequest}
 */
proto.SubnetCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetCreateRequest;
  return proto.SubnetCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetCreateRequest}
 */
proto.SubnetCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 4:
      var value = new proto.GatewayDefinition;
      reader.readMessage(value,proto.GatewayDefinition.deserializeBinaryFromReader);
      msg.setGateway(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setFailOver(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setDomain(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setKeepOnFailure(value);
      break;
    case 8:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setDefaultSshPort(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getGateway();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.GatewayDefinition.serializeBinaryToWriter
    );
  }
  f = message.getFailOver();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
  f = message.getDomain();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getKeepOnFailure();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
  f = message.getDefaultSshPort();
  if (f !== 0) {
    writer.writeUint32(
      8,
      f
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SubnetCreateRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetCreateRequest} returns this
*/
proto.SubnetCreateRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetCreateRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.SubnetCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string cidr = 3;
 * @return {string}
 */
proto.SubnetCreateRequest.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional GatewayDefinition gateway = 4;
 * @return {?proto.GatewayDefinition}
 */
proto.SubnetCreateRequest.prototype.getGateway = function() {
  return /** @type{?proto.GatewayDefinition} */ (
    jspb.Message.getWrapperField(this, proto.GatewayDefinition, 4));
};


/**
 * @param {?proto.GatewayDefinition|undefined} value
 * @return {!proto.SubnetCreateRequest} returns this
*/
proto.SubnetCreateRequest.prototype.setGateway = function(value) {
  return jspb.Message.setWrapperField(this, 4, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.clearGateway = function() {
  return this.setGateway(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetCreateRequest.prototype.hasGateway = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * optional bool fail_over = 5;
 * @return {boolean}
 */
proto.SubnetCreateRequest.prototype.getFailOver = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setFailOver = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};


/**
 * optional string domain = 6;
 * @return {string}
 */
proto.SubnetCreateRequest.prototype.getDomain = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setDomain = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional bool keep_on_failure = 7;
 * @return {boolean}
 */
proto.SubnetCreateRequest.prototype.getKeepOnFailure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setKeepOnFailure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};


/**
 * optional uint32 default_ssh_port = 8;
 * @return {number}
 */
proto.SubnetCreateRequest.prototype.getDefaultSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {number} value
 * @return {!proto.SubnetCreateRequest} returns this
 */
proto.SubnetCreateRequest.prototype.setDefaultSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 8, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.GatewayDefinition.prototype.toObject = function(opt_includeInstance) {
  return proto.GatewayDefinition.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.GatewayDefinition} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.GatewayDefinition.toObject = function(includeInstance, msg) {
  var f, obj = {
    cpu: jspb.Message.getFieldWithDefault(msg, 1, 0),
    ram: jspb.Message.getFloatingPointFieldWithDefault(msg, 2, 0.0),
    disk: jspb.Message.getFieldWithDefault(msg, 3, 0),
    imageId: jspb.Message.getFieldWithDefault(msg, 5, ""),
    name: jspb.Message.getFieldWithDefault(msg, 6, ""),
    gpuCount: jspb.Message.getFieldWithDefault(msg, 7, 0),
    gpuType: jspb.Message.getFieldWithDefault(msg, 8, ""),
    sizing: (f = msg.getSizing()) && proto.HostSizing.toObject(includeInstance, f),
    sizingAsString: jspb.Message.getFieldWithDefault(msg, 10, ""),
    sshPort: jspb.Message.getFieldWithDefault(msg, 11, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.GatewayDefinition}
 */
proto.GatewayDefinition.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.GatewayDefinition;
  return proto.GatewayDefinition.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.GatewayDefinition} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.GatewayDefinition}
 */
proto.GatewayDefinition.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setCpu(value);
      break;
    case 2:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setRam(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setDisk(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setImageId(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 7:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setGpuCount(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setGpuType(value);
      break;
    case 9:
      var value = new proto.HostSizing;
      reader.readMessage(value,proto.HostSizing.deserializeBinaryFromReader);
      msg.setSizing(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.setSizingAsString(value);
      break;
    case 11:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setSshPort(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.GatewayDefinition.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.GatewayDefinition.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.GatewayDefinition} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.GatewayDefinition.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getCpu();
  if (f !== 0) {
    writer.writeInt32(
      1,
      f
    );
  }
  f = message.getRam();
  if (f !== 0.0) {
    writer.writeFloat(
      2,
      f
    );
  }
  f = message.getDisk();
  if (f !== 0) {
    writer.writeInt32(
      3,
      f
    );
  }
  f = message.getImageId();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getGpuCount();
  if (f !== 0) {
    writer.writeInt32(
      7,
      f
    );
  }
  f = message.getGpuType();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getSizing();
  if (f != null) {
    writer.writeMessage(
      9,
      f,
      proto.HostSizing.serializeBinaryToWriter
    );
  }
  f = message.getSizingAsString();
  if (f.length > 0) {
    writer.writeString(
      10,
      f
    );
  }
  f = message.getSshPort();
  if (f !== 0) {
    writer.writeUint32(
      11,
      f
    );
  }
};


/**
 * optional int32 cpu = 1;
 * @return {number}
 */
proto.GatewayDefinition.prototype.getCpu = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {number} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setCpu = function(value) {
  return jspb.Message.setProto3IntField(this, 1, value);
};


/**
 * optional float ram = 2;
 * @return {number}
 */
proto.GatewayDefinition.prototype.getRam = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 2, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setRam = function(value) {
  return jspb.Message.setProto3FloatField(this, 2, value);
};


/**
 * optional int32 disk = 3;
 * @return {number}
 */
proto.GatewayDefinition.prototype.getDisk = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {number} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setDisk = function(value) {
  return jspb.Message.setProto3IntField(this, 3, value);
};


/**
 * optional string image_id = 5;
 * @return {string}
 */
proto.GatewayDefinition.prototype.getImageId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setImageId = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string name = 6;
 * @return {string}
 */
proto.GatewayDefinition.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional int32 gpu_count = 7;
 * @return {number}
 */
proto.GatewayDefinition.prototype.getGpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 7, 0));
};


/**
 * @param {number} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setGpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 7, value);
};


/**
 * optional string gpu_type = 8;
 * @return {string}
 */
proto.GatewayDefinition.prototype.getGpuType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setGpuType = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * optional HostSizing sizing = 9;
 * @return {?proto.HostSizing}
 */
proto.GatewayDefinition.prototype.getSizing = function() {
  return /** @type{?proto.HostSizing} */ (
    jspb.Message.getWrapperField(this, proto.HostSizing, 9));
};


/**
 * @param {?proto.HostSizing|undefined} value
 * @return {!proto.GatewayDefinition} returns this
*/
proto.GatewayDefinition.prototype.setSizing = function(value) {
  return jspb.Message.setWrapperField(this, 9, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.clearSizing = function() {
  return this.setSizing(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.GatewayDefinition.prototype.hasSizing = function() {
  return jspb.Message.getField(this, 9) != null;
};


/**
 * optional string sizing_as_string = 10;
 * @return {string}
 */
proto.GatewayDefinition.prototype.getSizingAsString = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 10, ""));
};


/**
 * @param {string} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setSizingAsString = function(value) {
  return jspb.Message.setProto3StringField(this, 10, value);
};


/**
 * optional uint32 ssh_port = 11;
 * @return {number}
 */
proto.GatewayDefinition.prototype.getSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 11, 0));
};


/**
 * @param {number} value
 * @return {!proto.GatewayDefinition} returns this
 */
proto.GatewayDefinition.prototype.setSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 11, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetInspectRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetInspectRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetInspectRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetInspectRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    subnet: (f = msg.getSubnet()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetInspectRequest}
 */
proto.SubnetInspectRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetInspectRequest;
  return proto.SubnetInspectRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetInspectRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetInspectRequest}
 */
proto.SubnetInspectRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setSubnet(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetInspectRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetInspectRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetInspectRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetInspectRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getSubnet();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SubnetInspectRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetInspectRequest} returns this
*/
proto.SubnetInspectRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetInspectRequest} returns this
 */
proto.SubnetInspectRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetInspectRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference subnet = 2;
 * @return {?proto.Reference}
 */
proto.SubnetInspectRequest.prototype.getSubnet = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetInspectRequest} returns this
*/
proto.SubnetInspectRequest.prototype.setSubnet = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetInspectRequest} returns this
 */
proto.SubnetInspectRequest.prototype.clearSubnet = function() {
  return this.setSubnet(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetInspectRequest.prototype.hasSubnet = function() {
  return jspb.Message.getField(this, 2) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    subnet: (f = msg.getSubnet()) && proto.Reference.toObject(includeInstance, f),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetDeleteRequest}
 */
proto.SubnetDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetDeleteRequest;
  return proto.SubnetDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetDeleteRequest}
 */
proto.SubnetDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setSubnet(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getSubnet();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SubnetDeleteRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetDeleteRequest} returns this
*/
proto.SubnetDeleteRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetDeleteRequest} returns this
 */
proto.SubnetDeleteRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetDeleteRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference subnet = 2;
 * @return {?proto.Reference}
 */
proto.SubnetDeleteRequest.prototype.getSubnet = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetDeleteRequest} returns this
*/
proto.SubnetDeleteRequest.prototype.setSubnet = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetDeleteRequest} returns this
 */
proto.SubnetDeleteRequest.prototype.clearSubnet = function() {
  return this.setSubnet(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetDeleteRequest.prototype.hasSubnet = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional bool force = 3;
 * @return {boolean}
 */
proto.SubnetDeleteRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SubnetDeleteRequest} returns this
 */
proto.SubnetDeleteRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.Subnet.repeatedFields_ = [4];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Subnet.prototype.toObject = function(opt_includeInstance) {
  return proto.Subnet.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Subnet} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Subnet.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cidr: jspb.Message.getFieldWithDefault(msg, 3, ""),
    gatewayIdsList: (f = jspb.Message.getRepeatedField(msg, 4)) == null ? undefined : f,
    virtualIp: (f = msg.getVirtualIp()) && proto.VirtualIp.toObject(includeInstance, f),
    failover: jspb.Message.getBooleanFieldWithDefault(msg, 6, false),
    state: jspb.Message.getFieldWithDefault(msg, 7, 0),
    networkId: jspb.Message.getFieldWithDefault(msg, 8, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Subnet}
 */
proto.Subnet.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Subnet;
  return proto.Subnet.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Subnet} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Subnet}
 */
proto.Subnet.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.addGatewayIds(value);
      break;
    case 5:
      var value = new proto.VirtualIp;
      reader.readMessage(value,proto.VirtualIp.deserializeBinaryFromReader);
      msg.setVirtualIp(value);
      break;
    case 6:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setFailover(value);
      break;
    case 7:
      var value = /** @type {!proto.SubnetState} */ (reader.readEnum());
      msg.setState(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setNetworkId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Subnet.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Subnet.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Subnet} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Subnet.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getGatewayIdsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      4,
      f
    );
  }
  f = message.getVirtualIp();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.VirtualIp.serializeBinaryToWriter
    );
  }
  f = message.getFailover();
  if (f) {
    writer.writeBool(
      6,
      f
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      7,
      f
    );
  }
  f = message.getNetworkId();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.Subnet.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.Subnet.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string cidr = 3;
 * @return {string}
 */
proto.Subnet.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * repeated string gateway_ids = 4;
 * @return {!Array<string>}
 */
proto.Subnet.prototype.getGatewayIdsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 4));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setGatewayIdsList = function(value) {
  return jspb.Message.setField(this, 4, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.addGatewayIds = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 4, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.clearGatewayIdsList = function() {
  return this.setGatewayIdsList([]);
};


/**
 * optional VirtualIp virtual_ip = 5;
 * @return {?proto.VirtualIp}
 */
proto.Subnet.prototype.getVirtualIp = function() {
  return /** @type{?proto.VirtualIp} */ (
    jspb.Message.getWrapperField(this, proto.VirtualIp, 5));
};


/**
 * @param {?proto.VirtualIp|undefined} value
 * @return {!proto.Subnet} returns this
*/
proto.Subnet.prototype.setVirtualIp = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.clearVirtualIp = function() {
  return this.setVirtualIp(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.Subnet.prototype.hasVirtualIp = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional bool failover = 6;
 * @return {boolean}
 */
proto.Subnet.prototype.getFailover = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 6, false));
};


/**
 * @param {boolean} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setFailover = function(value) {
  return jspb.Message.setProto3BooleanField(this, 6, value);
};


/**
 * optional SubnetState state = 7;
 * @return {!proto.SubnetState}
 */
proto.Subnet.prototype.getState = function() {
  return /** @type {!proto.SubnetState} */ (jspb.Message.getFieldWithDefault(this, 7, 0));
};


/**
 * @param {!proto.SubnetState} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 7, value);
};


/**
 * optional string network_id = 8;
 * @return {string}
 */
proto.Subnet.prototype.getNetworkId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.Subnet} returns this
 */
proto.Subnet.prototype.setNetworkId = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SubnetList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetList.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetList.toObject = function(includeInstance, msg) {
  var f, obj = {
    subnetsList: jspb.Message.toObjectList(msg.getSubnetsList(),
    proto.Subnet.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetList}
 */
proto.SubnetList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetList;
  return proto.SubnetList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetList}
 */
proto.SubnetList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Subnet;
      reader.readMessage(value,proto.Subnet.deserializeBinaryFromReader);
      msg.addSubnets(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSubnetsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Subnet.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Subnet subnets = 1;
 * @return {!Array<!proto.Subnet>}
 */
proto.SubnetList.prototype.getSubnetsList = function() {
  return /** @type{!Array<!proto.Subnet>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Subnet, 1));
};


/**
 * @param {!Array<!proto.Subnet>} value
 * @return {!proto.SubnetList} returns this
*/
proto.SubnetList.prototype.setSubnetsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Subnet=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Subnet}
 */
proto.SubnetList.prototype.addSubnets = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Subnet, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SubnetList} returns this
 */
proto.SubnetList.prototype.clearSubnetsList = function() {
  return this.setSubnetsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    all: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetListRequest}
 */
proto.SubnetListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetListRequest;
  return proto.SubnetListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetListRequest}
 */
proto.SubnetListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getAll();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SubnetListRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetListRequest} returns this
*/
proto.SubnetListRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetListRequest} returns this
 */
proto.SubnetListRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetListRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool all = 2;
 * @return {boolean}
 */
proto.SubnetListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SubnetListRequest} returns this
 */
proto.SubnetListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SubnetSecurityGroupBondsRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SubnetSecurityGroupBondsRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetSecurityGroupBondsRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    subnet: (f = msg.getSubnet()) && proto.Reference.toObject(includeInstance, f),
    kind: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SubnetSecurityGroupBondsRequest}
 */
proto.SubnetSecurityGroupBondsRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SubnetSecurityGroupBondsRequest;
  return proto.SubnetSecurityGroupBondsRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SubnetSecurityGroupBondsRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SubnetSecurityGroupBondsRequest}
 */
proto.SubnetSecurityGroupBondsRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setSubnet(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setKind(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SubnetSecurityGroupBondsRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SubnetSecurityGroupBondsRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SubnetSecurityGroupBondsRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getSubnet();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getKind();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetSecurityGroupBondsRequest} returns this
*/
proto.SubnetSecurityGroupBondsRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetSecurityGroupBondsRequest} returns this
 */
proto.SubnetSecurityGroupBondsRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference subnet = 2;
 * @return {?proto.Reference}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.getSubnet = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SubnetSecurityGroupBondsRequest} returns this
*/
proto.SubnetSecurityGroupBondsRequest.prototype.setSubnet = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SubnetSecurityGroupBondsRequest} returns this
 */
proto.SubnetSecurityGroupBondsRequest.prototype.clearSubnet = function() {
  return this.setSubnet(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.hasSubnet = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional string kind = 3;
 * @return {string}
 */
proto.SubnetSecurityGroupBondsRequest.prototype.getKind = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SubnetSecurityGroupBondsRequest} returns this
 */
proto.SubnetSecurityGroupBondsRequest.prototype.setKind = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostSizing.prototype.toObject = function(opt_includeInstance) {
  return proto.HostSizing.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostSizing} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostSizing.toObject = function(includeInstance, msg) {
  var f, obj = {
    minCpuCount: jspb.Message.getFieldWithDefault(msg, 1, 0),
    maxCpuCount: jspb.Message.getFieldWithDefault(msg, 2, 0),
    minRamSize: jspb.Message.getFloatingPointFieldWithDefault(msg, 3, 0.0),
    maxRamSize: jspb.Message.getFloatingPointFieldWithDefault(msg, 4, 0.0),
    minDiskSize: jspb.Message.getFieldWithDefault(msg, 5, 0),
    gpuCount: jspb.Message.getFieldWithDefault(msg, 6, 0),
    minCpuFreq: jspb.Message.getFloatingPointFieldWithDefault(msg, 7, 0.0),
    maxDiskSize: jspb.Message.getFieldWithDefault(msg, 8, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostSizing}
 */
proto.HostSizing.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostSizing;
  return proto.HostSizing.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostSizing} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostSizing}
 */
proto.HostSizing.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setMinCpuCount(value);
      break;
    case 2:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setMaxCpuCount(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setMinRamSize(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setMaxRamSize(value);
      break;
    case 5:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setMinDiskSize(value);
      break;
    case 6:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setGpuCount(value);
      break;
    case 7:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setMinCpuFreq(value);
      break;
    case 8:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setMaxDiskSize(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostSizing.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostSizing.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostSizing} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostSizing.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getMinCpuCount();
  if (f !== 0) {
    writer.writeInt32(
      1,
      f
    );
  }
  f = message.getMaxCpuCount();
  if (f !== 0) {
    writer.writeInt32(
      2,
      f
    );
  }
  f = message.getMinRamSize();
  if (f !== 0.0) {
    writer.writeFloat(
      3,
      f
    );
  }
  f = message.getMaxRamSize();
  if (f !== 0.0) {
    writer.writeFloat(
      4,
      f
    );
  }
  f = message.getMinDiskSize();
  if (f !== 0) {
    writer.writeInt32(
      5,
      f
    );
  }
  f = message.getGpuCount();
  if (f !== 0) {
    writer.writeInt32(
      6,
      f
    );
  }
  f = message.getMinCpuFreq();
  if (f !== 0.0) {
    writer.writeFloat(
      7,
      f
    );
  }
  f = message.getMaxDiskSize();
  if (f !== 0) {
    writer.writeInt32(
      8,
      f
    );
  }
};


/**
 * optional int32 min_cpu_count = 1;
 * @return {number}
 */
proto.HostSizing.prototype.getMinCpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMinCpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 1, value);
};


/**
 * optional int32 max_cpu_count = 2;
 * @return {number}
 */
proto.HostSizing.prototype.getMaxCpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMaxCpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 2, value);
};


/**
 * optional float min_ram_size = 3;
 * @return {number}
 */
proto.HostSizing.prototype.getMinRamSize = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 3, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMinRamSize = function(value) {
  return jspb.Message.setProto3FloatField(this, 3, value);
};


/**
 * optional float max_ram_size = 4;
 * @return {number}
 */
proto.HostSizing.prototype.getMaxRamSize = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 4, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMaxRamSize = function(value) {
  return jspb.Message.setProto3FloatField(this, 4, value);
};


/**
 * optional int32 min_disk_size = 5;
 * @return {number}
 */
proto.HostSizing.prototype.getMinDiskSize = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 5, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMinDiskSize = function(value) {
  return jspb.Message.setProto3IntField(this, 5, value);
};


/**
 * optional int32 gpu_count = 6;
 * @return {number}
 */
proto.HostSizing.prototype.getGpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 6, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setGpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 6, value);
};


/**
 * optional float min_cpu_freq = 7;
 * @return {number}
 */
proto.HostSizing.prototype.getMinCpuFreq = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 7, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMinCpuFreq = function(value) {
  return jspb.Message.setProto3FloatField(this, 7, value);
};


/**
 * optional int32 max_disk_size = 8;
 * @return {number}
 */
proto.HostSizing.prototype.getMaxDiskSize = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostSizing} returns this
 */
proto.HostSizing.prototype.setMaxDiskSize = function(value) {
  return jspb.Message.setProto3IntField(this, 8, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.HostDefinition.repeatedFields_ = [19];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostDefinition.prototype.toObject = function(opt_includeInstance) {
  return proto.HostDefinition.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostDefinition} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostDefinition.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    network: jspb.Message.getFieldWithDefault(msg, 3, ""),
    cpuCount: jspb.Message.getFieldWithDefault(msg, 4, 0),
    ram: jspb.Message.getFloatingPointFieldWithDefault(msg, 6, 0.0),
    disk: jspb.Message.getFieldWithDefault(msg, 7, 0),
    imageId: jspb.Message.getFieldWithDefault(msg, 9, ""),
    pb_public: jspb.Message.getBooleanFieldWithDefault(msg, 10, false),
    gpuCount: jspb.Message.getFieldWithDefault(msg, 11, 0),
    cpuFreq: jspb.Message.getFloatingPointFieldWithDefault(msg, 12, 0.0),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 13, false),
    sizing: (f = msg.getSizing()) && proto.HostSizing.toObject(includeInstance, f),
    domain: jspb.Message.getFieldWithDefault(msg, 15, ""),
    keepOnFailure: jspb.Message.getBooleanFieldWithDefault(msg, 16, false),
    sizingAsString: jspb.Message.getFieldWithDefault(msg, 17, ""),
    tenantId: jspb.Message.getFieldWithDefault(msg, 18, ""),
    subnetsList: (f = jspb.Message.getRepeatedField(msg, 19)) == null ? undefined : f,
    sshPort: jspb.Message.getFieldWithDefault(msg, 20, 0),
    single: jspb.Message.getBooleanFieldWithDefault(msg, 21, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostDefinition}
 */
proto.HostDefinition.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostDefinition;
  return proto.HostDefinition.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostDefinition} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostDefinition}
 */
proto.HostDefinition.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setNetwork(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setCpuCount(value);
      break;
    case 6:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setRam(value);
      break;
    case 7:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setDisk(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.setImageId(value);
      break;
    case 10:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setPublic(value);
      break;
    case 11:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setGpuCount(value);
      break;
    case 12:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setCpuFreq(value);
      break;
    case 13:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    case 14:
      var value = new proto.HostSizing;
      reader.readMessage(value,proto.HostSizing.deserializeBinaryFromReader);
      msg.setSizing(value);
      break;
    case 15:
      var value = /** @type {string} */ (reader.readString());
      msg.setDomain(value);
      break;
    case 16:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setKeepOnFailure(value);
      break;
    case 17:
      var value = /** @type {string} */ (reader.readString());
      msg.setSizingAsString(value);
      break;
    case 18:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 19:
      var value = /** @type {string} */ (reader.readString());
      msg.addSubnets(value);
      break;
    case 20:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setSshPort(value);
      break;
    case 21:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setSingle(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostDefinition.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostDefinition.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostDefinition} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostDefinition.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getNetwork();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getCpuCount();
  if (f !== 0) {
    writer.writeInt32(
      4,
      f
    );
  }
  f = message.getRam();
  if (f !== 0.0) {
    writer.writeFloat(
      6,
      f
    );
  }
  f = message.getDisk();
  if (f !== 0) {
    writer.writeInt32(
      7,
      f
    );
  }
  f = message.getImageId();
  if (f.length > 0) {
    writer.writeString(
      9,
      f
    );
  }
  f = message.getPublic();
  if (f) {
    writer.writeBool(
      10,
      f
    );
  }
  f = message.getGpuCount();
  if (f !== 0) {
    writer.writeInt32(
      11,
      f
    );
  }
  f = message.getCpuFreq();
  if (f !== 0.0) {
    writer.writeFloat(
      12,
      f
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      13,
      f
    );
  }
  f = message.getSizing();
  if (f != null) {
    writer.writeMessage(
      14,
      f,
      proto.HostSizing.serializeBinaryToWriter
    );
  }
  f = message.getDomain();
  if (f.length > 0) {
    writer.writeString(
      15,
      f
    );
  }
  f = message.getKeepOnFailure();
  if (f) {
    writer.writeBool(
      16,
      f
    );
  }
  f = message.getSizingAsString();
  if (f.length > 0) {
    writer.writeString(
      17,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      18,
      f
    );
  }
  f = message.getSubnetsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      19,
      f
    );
  }
  f = message.getSshPort();
  if (f !== 0) {
    writer.writeInt32(
      20,
      f
    );
  }
  f = message.getSingle();
  if (f) {
    writer.writeBool(
      21,
      f
    );
  }
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.HostDefinition.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string network = 3;
 * @return {string}
 */
proto.HostDefinition.prototype.getNetwork = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setNetwork = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional int32 cpu_count = 4;
 * @return {number}
 */
proto.HostDefinition.prototype.getCpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setCpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional float ram = 6;
 * @return {number}
 */
proto.HostDefinition.prototype.getRam = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 6, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setRam = function(value) {
  return jspb.Message.setProto3FloatField(this, 6, value);
};


/**
 * optional int32 disk = 7;
 * @return {number}
 */
proto.HostDefinition.prototype.getDisk = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 7, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setDisk = function(value) {
  return jspb.Message.setProto3IntField(this, 7, value);
};


/**
 * optional string image_id = 9;
 * @return {string}
 */
proto.HostDefinition.prototype.getImageId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 9, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setImageId = function(value) {
  return jspb.Message.setProto3StringField(this, 9, value);
};


/**
 * optional bool public = 10;
 * @return {boolean}
 */
proto.HostDefinition.prototype.getPublic = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 10, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setPublic = function(value) {
  return jspb.Message.setProto3BooleanField(this, 10, value);
};


/**
 * optional int32 gpu_count = 11;
 * @return {number}
 */
proto.HostDefinition.prototype.getGpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 11, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setGpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 11, value);
};


/**
 * optional float cpu_freq = 12;
 * @return {number}
 */
proto.HostDefinition.prototype.getCpuFreq = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 12, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setCpuFreq = function(value) {
  return jspb.Message.setProto3FloatField(this, 12, value);
};


/**
 * optional bool force = 13;
 * @return {boolean}
 */
proto.HostDefinition.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 13, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 13, value);
};


/**
 * optional HostSizing sizing = 14;
 * @return {?proto.HostSizing}
 */
proto.HostDefinition.prototype.getSizing = function() {
  return /** @type{?proto.HostSizing} */ (
    jspb.Message.getWrapperField(this, proto.HostSizing, 14));
};


/**
 * @param {?proto.HostSizing|undefined} value
 * @return {!proto.HostDefinition} returns this
*/
proto.HostDefinition.prototype.setSizing = function(value) {
  return jspb.Message.setWrapperField(this, 14, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.clearSizing = function() {
  return this.setSizing(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.HostDefinition.prototype.hasSizing = function() {
  return jspb.Message.getField(this, 14) != null;
};


/**
 * optional string domain = 15;
 * @return {string}
 */
proto.HostDefinition.prototype.getDomain = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 15, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setDomain = function(value) {
  return jspb.Message.setProto3StringField(this, 15, value);
};


/**
 * optional bool keep_on_failure = 16;
 * @return {boolean}
 */
proto.HostDefinition.prototype.getKeepOnFailure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 16, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setKeepOnFailure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 16, value);
};


/**
 * optional string sizing_as_string = 17;
 * @return {string}
 */
proto.HostDefinition.prototype.getSizingAsString = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 17, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setSizingAsString = function(value) {
  return jspb.Message.setProto3StringField(this, 17, value);
};


/**
 * optional string tenant_id = 18;
 * @return {string}
 */
proto.HostDefinition.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 18, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 18, value);
};


/**
 * repeated string subnets = 19;
 * @return {!Array<string>}
 */
proto.HostDefinition.prototype.getSubnetsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 19));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setSubnetsList = function(value) {
  return jspb.Message.setField(this, 19, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.addSubnets = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 19, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.clearSubnetsList = function() {
  return this.setSubnetsList([]);
};


/**
 * optional int32 ssh_port = 20;
 * @return {number}
 */
proto.HostDefinition.prototype.getSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 20, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 20, value);
};


/**
 * optional bool single = 21;
 * @return {boolean}
 */
proto.HostDefinition.prototype.getSingle = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 21, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostDefinition} returns this
 */
proto.HostDefinition.prototype.setSingle = function(value) {
  return jspb.Message.setProto3BooleanField(this, 21, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.Host.repeatedFields_ = [12,19];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.Host.prototype.toObject = function(opt_includeInstance) {
  return proto.Host.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.Host} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Host.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cpu: jspb.Message.getFieldWithDefault(msg, 3, 0),
    ram: jspb.Message.getFloatingPointFieldWithDefault(msg, 4, 0.0),
    disk: jspb.Message.getFieldWithDefault(msg, 5, 0),
    publicIp: jspb.Message.getFieldWithDefault(msg, 6, ""),
    privateIp: jspb.Message.getFieldWithDefault(msg, 7, ""),
    state: jspb.Message.getFieldWithDefault(msg, 8, 0),
    privateKey: jspb.Message.getFieldWithDefault(msg, 9, ""),
    gatewayId: jspb.Message.getFieldWithDefault(msg, 10, ""),
    osKind: jspb.Message.getFieldWithDefault(msg, 11, ""),
    attachedVolumeNamesList: (f = jspb.Message.getRepeatedField(msg, 12)) == null ? undefined : f,
    password: jspb.Message.getFieldWithDefault(msg, 13, ""),
    sshPort: jspb.Message.getFieldWithDefault(msg, 14, 0),
    stateLabel: jspb.Message.getFieldWithDefault(msg, 15, ""),
    creationDate: jspb.Message.getFieldWithDefault(msg, 16, ""),
    managed: jspb.Message.getBooleanFieldWithDefault(msg, 17, false),
    template: jspb.Message.getFieldWithDefault(msg, 18, ""),
    labelsList: jspb.Message.toObjectList(msg.getLabelsList(),
    proto.HostLabelResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.Host}
 */
proto.Host.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.Host;
  return proto.Host.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.Host} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.Host}
 */
proto.Host.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setCpu(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readFloat());
      msg.setRam(value);
      break;
    case 5:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setDisk(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setPublicIp(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrivateIp(value);
      break;
    case 8:
      var value = /** @type {!proto.HostState} */ (reader.readEnum());
      msg.setState(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrivateKey(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewayId(value);
      break;
    case 11:
      var value = /** @type {string} */ (reader.readString());
      msg.setOsKind(value);
      break;
    case 12:
      var value = /** @type {string} */ (reader.readString());
      msg.addAttachedVolumeNames(value);
      break;
    case 13:
      var value = /** @type {string} */ (reader.readString());
      msg.setPassword(value);
      break;
    case 14:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setSshPort(value);
      break;
    case 15:
      var value = /** @type {string} */ (reader.readString());
      msg.setStateLabel(value);
      break;
    case 16:
      var value = /** @type {string} */ (reader.readString());
      msg.setCreationDate(value);
      break;
    case 17:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setManaged(value);
      break;
    case 18:
      var value = /** @type {string} */ (reader.readString());
      msg.setTemplate(value);
      break;
    case 19:
      var value = new proto.HostLabelResponse;
      reader.readMessage(value,proto.HostLabelResponse.deserializeBinaryFromReader);
      msg.addLabels(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.Host.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.Host.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.Host} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.Host.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCpu();
  if (f !== 0) {
    writer.writeInt32(
      3,
      f
    );
  }
  f = message.getRam();
  if (f !== 0.0) {
    writer.writeFloat(
      4,
      f
    );
  }
  f = message.getDisk();
  if (f !== 0) {
    writer.writeInt32(
      5,
      f
    );
  }
  f = message.getPublicIp();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getPrivateIp();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      8,
      f
    );
  }
  f = message.getPrivateKey();
  if (f.length > 0) {
    writer.writeString(
      9,
      f
    );
  }
  f = message.getGatewayId();
  if (f.length > 0) {
    writer.writeString(
      10,
      f
    );
  }
  f = message.getOsKind();
  if (f.length > 0) {
    writer.writeString(
      11,
      f
    );
  }
  f = message.getAttachedVolumeNamesList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      12,
      f
    );
  }
  f = message.getPassword();
  if (f.length > 0) {
    writer.writeString(
      13,
      f
    );
  }
  f = message.getSshPort();
  if (f !== 0) {
    writer.writeInt32(
      14,
      f
    );
  }
  f = message.getStateLabel();
  if (f.length > 0) {
    writer.writeString(
      15,
      f
    );
  }
  f = message.getCreationDate();
  if (f.length > 0) {
    writer.writeString(
      16,
      f
    );
  }
  f = message.getManaged();
  if (f) {
    writer.writeBool(
      17,
      f
    );
  }
  f = message.getTemplate();
  if (f.length > 0) {
    writer.writeString(
      18,
      f
    );
  }
  f = message.getLabelsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      19,
      f,
      proto.HostLabelResponse.serializeBinaryToWriter
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.Host.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.Host.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional int32 cpu = 3;
 * @return {number}
 */
proto.Host.prototype.getCpu = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {number} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setCpu = function(value) {
  return jspb.Message.setProto3IntField(this, 3, value);
};


/**
 * optional float ram = 4;
 * @return {number}
 */
proto.Host.prototype.getRam = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 4, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setRam = function(value) {
  return jspb.Message.setProto3FloatField(this, 4, value);
};


/**
 * optional int32 disk = 5;
 * @return {number}
 */
proto.Host.prototype.getDisk = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 5, 0));
};


/**
 * @param {number} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setDisk = function(value) {
  return jspb.Message.setProto3IntField(this, 5, value);
};


/**
 * optional string public_ip = 6;
 * @return {string}
 */
proto.Host.prototype.getPublicIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setPublicIp = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string private_ip = 7;
 * @return {string}
 */
proto.Host.prototype.getPrivateIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setPrivateIp = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional HostState state = 8;
 * @return {!proto.HostState}
 */
proto.Host.prototype.getState = function() {
  return /** @type {!proto.HostState} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {!proto.HostState} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 8, value);
};


/**
 * optional string private_key = 9;
 * @return {string}
 */
proto.Host.prototype.getPrivateKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 9, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setPrivateKey = function(value) {
  return jspb.Message.setProto3StringField(this, 9, value);
};


/**
 * optional string gateway_id = 10;
 * @return {string}
 */
proto.Host.prototype.getGatewayId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 10, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setGatewayId = function(value) {
  return jspb.Message.setProto3StringField(this, 10, value);
};


/**
 * optional string os_kind = 11;
 * @return {string}
 */
proto.Host.prototype.getOsKind = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 11, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setOsKind = function(value) {
  return jspb.Message.setProto3StringField(this, 11, value);
};


/**
 * repeated string attached_volume_names = 12;
 * @return {!Array<string>}
 */
proto.Host.prototype.getAttachedVolumeNamesList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 12));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setAttachedVolumeNamesList = function(value) {
  return jspb.Message.setField(this, 12, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.addAttachedVolumeNames = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 12, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.clearAttachedVolumeNamesList = function() {
  return this.setAttachedVolumeNamesList([]);
};


/**
 * optional string password = 13;
 * @return {string}
 */
proto.Host.prototype.getPassword = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 13, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setPassword = function(value) {
  return jspb.Message.setProto3StringField(this, 13, value);
};


/**
 * optional int32 ssh_port = 14;
 * @return {number}
 */
proto.Host.prototype.getSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 14, 0));
};


/**
 * @param {number} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 14, value);
};


/**
 * optional string state_label = 15;
 * @return {string}
 */
proto.Host.prototype.getStateLabel = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 15, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setStateLabel = function(value) {
  return jspb.Message.setProto3StringField(this, 15, value);
};


/**
 * optional string creation_date = 16;
 * @return {string}
 */
proto.Host.prototype.getCreationDate = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 16, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setCreationDate = function(value) {
  return jspb.Message.setProto3StringField(this, 16, value);
};


/**
 * optional bool managed = 17;
 * @return {boolean}
 */
proto.Host.prototype.getManaged = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 17, false));
};


/**
 * @param {boolean} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setManaged = function(value) {
  return jspb.Message.setProto3BooleanField(this, 17, value);
};


/**
 * optional string template = 18;
 * @return {string}
 */
proto.Host.prototype.getTemplate = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 18, ""));
};


/**
 * @param {string} value
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.setTemplate = function(value) {
  return jspb.Message.setProto3StringField(this, 18, value);
};


/**
 * repeated HostLabelResponse labels = 19;
 * @return {!Array<!proto.HostLabelResponse>}
 */
proto.Host.prototype.getLabelsList = function() {
  return /** @type{!Array<!proto.HostLabelResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.HostLabelResponse, 19));
};


/**
 * @param {!Array<!proto.HostLabelResponse>} value
 * @return {!proto.Host} returns this
*/
proto.Host.prototype.setLabelsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 19, value);
};


/**
 * @param {!proto.HostLabelResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.HostLabelResponse}
 */
proto.Host.prototype.addLabels = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 19, opt_value, proto.HostLabelResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.Host} returns this
 */
proto.Host.prototype.clearLabelsList = function() {
  return this.setLabelsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostStatus.prototype.toObject = function(opt_includeInstance) {
  return proto.HostStatus.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostStatus} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostStatus.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    status: jspb.Message.getFieldWithDefault(msg, 2, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostStatus}
 */
proto.HostStatus.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostStatus;
  return proto.HostStatus.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostStatus} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostStatus}
 */
proto.HostStatus.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {!proto.HostState} */ (reader.readEnum());
      msg.setStatus(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostStatus.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostStatus.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostStatus} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostStatus.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getStatus();
  if (f !== 0.0) {
    writer.writeEnum(
      2,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.HostStatus.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostStatus} returns this
 */
proto.HostStatus.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional HostState status = 2;
 * @return {!proto.HostState}
 */
proto.HostStatus.prototype.getStatus = function() {
  return /** @type {!proto.HostState} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {!proto.HostState} value
 * @return {!proto.HostStatus} returns this
 */
proto.HostStatus.prototype.setStatus = function(value) {
  return jspb.Message.setProto3EnumField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.HostList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostList.prototype.toObject = function(opt_includeInstance) {
  return proto.HostList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostList.toObject = function(includeInstance, msg) {
  var f, obj = {
    hostsList: jspb.Message.toObjectList(msg.getHostsList(),
    proto.Host.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostList}
 */
proto.HostList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostList;
  return proto.HostList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostList}
 */
proto.HostList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Host;
      reader.readMessage(value,proto.Host.deserializeBinaryFromReader);
      msg.addHosts(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHostsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Host.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Host hosts = 1;
 * @return {!Array<!proto.Host>}
 */
proto.HostList.prototype.getHostsList = function() {
  return /** @type{!Array<!proto.Host>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Host, 1));
};


/**
 * @param {!Array<!proto.Host>} value
 * @return {!proto.HostList} returns this
*/
proto.HostList.prototype.setHostsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Host=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Host}
 */
proto.HostList.prototype.addHosts = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Host, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.HostList} returns this
 */
proto.HostList.prototype.clearHostsList = function() {
  return this.setHostsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SshConfig.prototype.toObject = function(opt_includeInstance) {
  return proto.SshConfig.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SshConfig} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshConfig.toObject = function(includeInstance, msg) {
  var f, obj = {
    user: jspb.Message.getFieldWithDefault(msg, 1, ""),
    host: jspb.Message.getFieldWithDefault(msg, 2, ""),
    privateKey: jspb.Message.getFieldWithDefault(msg, 3, ""),
    port: jspb.Message.getFieldWithDefault(msg, 4, 0),
    gateway: (f = msg.getGateway()) && proto.SshConfig.toObject(includeInstance, f),
    secondaryGateway: (f = msg.getSecondaryGateway()) && proto.SshConfig.toObject(includeInstance, f),
    hostName: jspb.Message.getFieldWithDefault(msg, 7, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SshConfig}
 */
proto.SshConfig.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SshConfig;
  return proto.SshConfig.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SshConfig} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SshConfig}
 */
proto.SshConfig.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setUser(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setHost(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrivateKey(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setPort(value);
      break;
    case 5:
      var value = new proto.SshConfig;
      reader.readMessage(value,proto.SshConfig.deserializeBinaryFromReader);
      msg.setGateway(value);
      break;
    case 6:
      var value = new proto.SshConfig;
      reader.readMessage(value,proto.SshConfig.deserializeBinaryFromReader);
      msg.setSecondaryGateway(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setHostName(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SshConfig.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SshConfig.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SshConfig} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshConfig.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getUser();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getHost();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getPrivateKey();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getPort();
  if (f !== 0) {
    writer.writeInt32(
      4,
      f
    );
  }
  f = message.getGateway();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.SshConfig.serializeBinaryToWriter
    );
  }
  f = message.getSecondaryGateway();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.SshConfig.serializeBinaryToWriter
    );
  }
  f = message.getHostName();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
};


/**
 * optional string user = 1;
 * @return {string}
 */
proto.SshConfig.prototype.getUser = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.setUser = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string host = 2;
 * @return {string}
 */
proto.SshConfig.prototype.getHost = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.setHost = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string private_key = 3;
 * @return {string}
 */
proto.SshConfig.prototype.getPrivateKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.setPrivateKey = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional int32 port = 4;
 * @return {number}
 */
proto.SshConfig.prototype.getPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {number} value
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.setPort = function(value) {
  return jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional SshConfig gateway = 5;
 * @return {?proto.SshConfig}
 */
proto.SshConfig.prototype.getGateway = function() {
  return /** @type{?proto.SshConfig} */ (
    jspb.Message.getWrapperField(this, proto.SshConfig, 5));
};


/**
 * @param {?proto.SshConfig|undefined} value
 * @return {!proto.SshConfig} returns this
*/
proto.SshConfig.prototype.setGateway = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.clearGateway = function() {
  return this.setGateway(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SshConfig.prototype.hasGateway = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional SshConfig secondary_gateway = 6;
 * @return {?proto.SshConfig}
 */
proto.SshConfig.prototype.getSecondaryGateway = function() {
  return /** @type{?proto.SshConfig} */ (
    jspb.Message.getWrapperField(this, proto.SshConfig, 6));
};


/**
 * @param {?proto.SshConfig|undefined} value
 * @return {!proto.SshConfig} returns this
*/
proto.SshConfig.prototype.setSecondaryGateway = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.clearSecondaryGateway = function() {
  return this.setSecondaryGateway(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SshConfig.prototype.hasSecondaryGateway = function() {
  return jspb.Message.getField(this, 6) != null;
};


/**
 * optional string host_name = 7;
 * @return {string}
 */
proto.SshConfig.prototype.getHostName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshConfig} returns this
 */
proto.SshConfig.prototype.setHostName = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.HostListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostListRequest}
 */
proto.HostListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostListRequest;
  return proto.HostListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostListRequest}
 */
proto.HostListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.HostListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostListRequest} returns this
 */
proto.HostListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.HostListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostListRequest} returns this
 */
proto.HostListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostLabelRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.HostLabelRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostLabelRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostLabelRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    label: (f = msg.getLabel()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostLabelRequest}
 */
proto.HostLabelRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostLabelRequest;
  return proto.HostLabelRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostLabelRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostLabelRequest}
 */
proto.HostLabelRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setLabel(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostLabelRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostLabelRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostLabelRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostLabelRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getLabel();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference Host = 1;
 * @return {?proto.Reference}
 */
proto.HostLabelRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.HostLabelRequest} returns this
*/
proto.HostLabelRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.HostLabelRequest} returns this
 */
proto.HostLabelRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.HostLabelRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference Label = 2;
 * @return {?proto.Reference}
 */
proto.HostLabelRequest.prototype.getLabel = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.HostLabelRequest} returns this
*/
proto.HostLabelRequest.prototype.setLabel = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.HostLabelRequest} returns this
 */
proto.HostLabelRequest.prototype.clearLabel = function() {
  return this.setLabel(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.HostLabelRequest.prototype.hasLabel = function() {
  return jspb.Message.getField(this, 2) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostLabelResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.HostLabelResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostLabelResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostLabelResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    hasDefault: jspb.Message.getBooleanFieldWithDefault(msg, 3, false),
    defaultValue: jspb.Message.getFieldWithDefault(msg, 4, ""),
    value: jspb.Message.getFieldWithDefault(msg, 5, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostLabelResponse}
 */
proto.HostLabelResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostLabelResponse;
  return proto.HostLabelResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostLabelResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostLabelResponse}
 */
proto.HostLabelResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setHasDefault(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setDefaultValue(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostLabelResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostLabelResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostLabelResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostLabelResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getHasDefault();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
  f = message.getDefaultValue();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getValue();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.HostLabelResponse.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostLabelResponse} returns this
 */
proto.HostLabelResponse.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.HostLabelResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostLabelResponse} returns this
 */
proto.HostLabelResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional bool has_default = 3;
 * @return {boolean}
 */
proto.HostLabelResponse.prototype.getHasDefault = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.HostLabelResponse} returns this
 */
proto.HostLabelResponse.prototype.setHasDefault = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};


/**
 * optional string default_value = 4;
 * @return {string}
 */
proto.HostLabelResponse.prototype.getDefaultValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostLabelResponse} returns this
 */
proto.HostLabelResponse.prototype.setDefaultValue = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string value = 5;
 * @return {string}
 */
proto.HostLabelResponse.prototype.getValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostLabelResponse} returns this
 */
proto.HostLabelResponse.prototype.setValue = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.HostTemplate.prototype.toObject = function(opt_includeInstance) {
  return proto.HostTemplate.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.HostTemplate} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostTemplate.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    cores: jspb.Message.getFieldWithDefault(msg, 3, 0),
    ram: jspb.Message.getFieldWithDefault(msg, 4, 0),
    disk: jspb.Message.getFieldWithDefault(msg, 5, 0),
    gpuCount: jspb.Message.getFieldWithDefault(msg, 6, 0),
    gpuType: jspb.Message.getFieldWithDefault(msg, 7, ""),
    scanned: (f = msg.getScanned()) && proto.ScannedInfo.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.HostTemplate}
 */
proto.HostTemplate.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.HostTemplate;
  return proto.HostTemplate.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.HostTemplate} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.HostTemplate}
 */
proto.HostTemplate.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setCores(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setRam(value);
      break;
    case 5:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setDisk(value);
      break;
    case 6:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setGpuCount(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setGpuType(value);
      break;
    case 8:
      var value = new proto.ScannedInfo;
      reader.readMessage(value,proto.ScannedInfo.deserializeBinaryFromReader);
      msg.setScanned(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.HostTemplate.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.HostTemplate.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.HostTemplate} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.HostTemplate.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getCores();
  if (f !== 0) {
    writer.writeInt32(
      3,
      f
    );
  }
  f = message.getRam();
  if (f !== 0) {
    writer.writeInt32(
      4,
      f
    );
  }
  f = message.getDisk();
  if (f !== 0) {
    writer.writeInt32(
      5,
      f
    );
  }
  f = message.getGpuCount();
  if (f !== 0) {
    writer.writeInt32(
      6,
      f
    );
  }
  f = message.getGpuType();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getScanned();
  if (f != null) {
    writer.writeMessage(
      8,
      f,
      proto.ScannedInfo.serializeBinaryToWriter
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.HostTemplate.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.HostTemplate.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional int32 cores = 3;
 * @return {number}
 */
proto.HostTemplate.prototype.getCores = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setCores = function(value) {
  return jspb.Message.setProto3IntField(this, 3, value);
};


/**
 * optional int32 ram = 4;
 * @return {number}
 */
proto.HostTemplate.prototype.getRam = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setRam = function(value) {
  return jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional int32 disk = 5;
 * @return {number}
 */
proto.HostTemplate.prototype.getDisk = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 5, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setDisk = function(value) {
  return jspb.Message.setProto3IntField(this, 5, value);
};


/**
 * optional int32 gpu_count = 6;
 * @return {number}
 */
proto.HostTemplate.prototype.getGpuCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 6, 0));
};


/**
 * @param {number} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setGpuCount = function(value) {
  return jspb.Message.setProto3IntField(this, 6, value);
};


/**
 * optional string gpu_type = 7;
 * @return {string}
 */
proto.HostTemplate.prototype.getGpuType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.setGpuType = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional ScannedInfo scanned = 8;
 * @return {?proto.ScannedInfo}
 */
proto.HostTemplate.prototype.getScanned = function() {
  return /** @type{?proto.ScannedInfo} */ (
    jspb.Message.getWrapperField(this, proto.ScannedInfo, 8));
};


/**
 * @param {?proto.ScannedInfo|undefined} value
 * @return {!proto.HostTemplate} returns this
*/
proto.HostTemplate.prototype.setScanned = function(value) {
  return jspb.Message.setWrapperField(this, 8, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.HostTemplate} returns this
 */
proto.HostTemplate.prototype.clearScanned = function() {
  return this.setScanned(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.HostTemplate.prototype.hasScanned = function() {
  return jspb.Message.getField(this, 8) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ScannedInfo.repeatedFields_ = [25];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ScannedInfo.prototype.toObject = function(opt_includeInstance) {
  return proto.ScannedInfo.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ScannedInfo} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScannedInfo.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantName: jspb.Message.getFieldWithDefault(msg, 1, ""),
    templateId: jspb.Message.getFieldWithDefault(msg, 2, ""),
    templateName: jspb.Message.getFieldWithDefault(msg, 3, ""),
    imageId: jspb.Message.getFieldWithDefault(msg, 4, ""),
    imageName: jspb.Message.getFieldWithDefault(msg, 5, ""),
    lastUpdated: jspb.Message.getFieldWithDefault(msg, 6, ""),
    numberOfCpu: jspb.Message.getFieldWithDefault(msg, 7, 0),
    numberOfCore: jspb.Message.getFieldWithDefault(msg, 8, 0),
    numberOfSocket: jspb.Message.getFieldWithDefault(msg, 9, 0),
    cpuFrequencyGhz: jspb.Message.getFloatingPointFieldWithDefault(msg, 10, 0.0),
    cpuArch: jspb.Message.getFieldWithDefault(msg, 11, ""),
    hypervisor: jspb.Message.getFieldWithDefault(msg, 12, ""),
    cpuModel: jspb.Message.getFieldWithDefault(msg, 13, ""),
    ramSizeGb: jspb.Message.getFloatingPointFieldWithDefault(msg, 14, 0.0),
    ramFreq: jspb.Message.getFloatingPointFieldWithDefault(msg, 15, 0.0),
    gpu: jspb.Message.getFieldWithDefault(msg, 16, 0),
    gpuModel: jspb.Message.getFieldWithDefault(msg, 17, ""),
    diskSizeGb: jspb.Message.getFieldWithDefault(msg, 18, 0),
    mainDiskType: jspb.Message.getFieldWithDefault(msg, 19, ""),
    mainDiskSpeedMbps: jspb.Message.getFloatingPointFieldWithDefault(msg, 20, 0.0),
    sampleNetSpeedKbps: jspb.Message.getFloatingPointFieldWithDefault(msg, 21, 0.0),
    ephDiskSizeGb: jspb.Message.getFieldWithDefault(msg, 22, 0),
    priceInDollarsSecond: jspb.Message.getFloatingPointFieldWithDefault(msg, 23, 0.0),
    priceInDollarsHour: jspb.Message.getFloatingPointFieldWithDefault(msg, 24, 0.0),
    pricesList: jspb.Message.toObjectList(msg.getPricesList(),
    proto.PriceInfo.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ScannedInfo}
 */
proto.ScannedInfo.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ScannedInfo;
  return proto.ScannedInfo.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ScannedInfo} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ScannedInfo}
 */
proto.ScannedInfo.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTemplateId(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setTemplateName(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setImageId(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setImageName(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setLastUpdated(value);
      break;
    case 7:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setNumberOfCpu(value);
      break;
    case 8:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setNumberOfCore(value);
      break;
    case 9:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setNumberOfSocket(value);
      break;
    case 10:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setCpuFrequencyGhz(value);
      break;
    case 11:
      var value = /** @type {string} */ (reader.readString());
      msg.setCpuArch(value);
      break;
    case 12:
      var value = /** @type {string} */ (reader.readString());
      msg.setHypervisor(value);
      break;
    case 13:
      var value = /** @type {string} */ (reader.readString());
      msg.setCpuModel(value);
      break;
    case 14:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setRamSizeGb(value);
      break;
    case 15:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setRamFreq(value);
      break;
    case 16:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setGpu(value);
      break;
    case 17:
      var value = /** @type {string} */ (reader.readString());
      msg.setGpuModel(value);
      break;
    case 18:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setDiskSizeGb(value);
      break;
    case 19:
      var value = /** @type {string} */ (reader.readString());
      msg.setMainDiskType(value);
      break;
    case 20:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setMainDiskSpeedMbps(value);
      break;
    case 21:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setSampleNetSpeedKbps(value);
      break;
    case 22:
      var value = /** @type {number} */ (reader.readInt64());
      msg.setEphDiskSizeGb(value);
      break;
    case 23:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setPriceInDollarsSecond(value);
      break;
    case 24:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setPriceInDollarsHour(value);
      break;
    case 25:
      var value = new proto.PriceInfo;
      reader.readMessage(value,proto.PriceInfo.deserializeBinaryFromReader);
      msg.addPrices(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ScannedInfo.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ScannedInfo.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ScannedInfo} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ScannedInfo.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getTemplateId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getTemplateName();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getImageId();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getImageName();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getLastUpdated();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getNumberOfCpu();
  if (f !== 0) {
    writer.writeInt64(
      7,
      f
    );
  }
  f = message.getNumberOfCore();
  if (f !== 0) {
    writer.writeInt64(
      8,
      f
    );
  }
  f = message.getNumberOfSocket();
  if (f !== 0) {
    writer.writeInt64(
      9,
      f
    );
  }
  f = message.getCpuFrequencyGhz();
  if (f !== 0.0) {
    writer.writeDouble(
      10,
      f
    );
  }
  f = message.getCpuArch();
  if (f.length > 0) {
    writer.writeString(
      11,
      f
    );
  }
  f = message.getHypervisor();
  if (f.length > 0) {
    writer.writeString(
      12,
      f
    );
  }
  f = message.getCpuModel();
  if (f.length > 0) {
    writer.writeString(
      13,
      f
    );
  }
  f = message.getRamSizeGb();
  if (f !== 0.0) {
    writer.writeDouble(
      14,
      f
    );
  }
  f = message.getRamFreq();
  if (f !== 0.0) {
    writer.writeDouble(
      15,
      f
    );
  }
  f = message.getGpu();
  if (f !== 0) {
    writer.writeInt64(
      16,
      f
    );
  }
  f = message.getGpuModel();
  if (f.length > 0) {
    writer.writeString(
      17,
      f
    );
  }
  f = message.getDiskSizeGb();
  if (f !== 0) {
    writer.writeInt64(
      18,
      f
    );
  }
  f = message.getMainDiskType();
  if (f.length > 0) {
    writer.writeString(
      19,
      f
    );
  }
  f = message.getMainDiskSpeedMbps();
  if (f !== 0.0) {
    writer.writeDouble(
      20,
      f
    );
  }
  f = message.getSampleNetSpeedKbps();
  if (f !== 0.0) {
    writer.writeDouble(
      21,
      f
    );
  }
  f = message.getEphDiskSizeGb();
  if (f !== 0) {
    writer.writeInt64(
      22,
      f
    );
  }
  f = message.getPriceInDollarsSecond();
  if (f !== 0.0) {
    writer.writeDouble(
      23,
      f
    );
  }
  f = message.getPriceInDollarsHour();
  if (f !== 0.0) {
    writer.writeDouble(
      24,
      f
    );
  }
  f = message.getPricesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      25,
      f,
      proto.PriceInfo.serializeBinaryToWriter
    );
  }
};


/**
 * optional string tenant_name = 1;
 * @return {string}
 */
proto.ScannedInfo.prototype.getTenantName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setTenantName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string template_id = 2;
 * @return {string}
 */
proto.ScannedInfo.prototype.getTemplateId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setTemplateId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string template_name = 3;
 * @return {string}
 */
proto.ScannedInfo.prototype.getTemplateName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setTemplateName = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string image_id = 4;
 * @return {string}
 */
proto.ScannedInfo.prototype.getImageId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setImageId = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string image_name = 5;
 * @return {string}
 */
proto.ScannedInfo.prototype.getImageName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setImageName = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string last_updated = 6;
 * @return {string}
 */
proto.ScannedInfo.prototype.getLastUpdated = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setLastUpdated = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional int64 number_of_cpu = 7;
 * @return {number}
 */
proto.ScannedInfo.prototype.getNumberOfCpu = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 7, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setNumberOfCpu = function(value) {
  return jspb.Message.setProto3IntField(this, 7, value);
};


/**
 * optional int64 number_of_core = 8;
 * @return {number}
 */
proto.ScannedInfo.prototype.getNumberOfCore = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setNumberOfCore = function(value) {
  return jspb.Message.setProto3IntField(this, 8, value);
};


/**
 * optional int64 number_of_socket = 9;
 * @return {number}
 */
proto.ScannedInfo.prototype.getNumberOfSocket = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 9, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setNumberOfSocket = function(value) {
  return jspb.Message.setProto3IntField(this, 9, value);
};


/**
 * optional double cpu_frequency_ghz = 10;
 * @return {number}
 */
proto.ScannedInfo.prototype.getCpuFrequencyGhz = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 10, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setCpuFrequencyGhz = function(value) {
  return jspb.Message.setProto3FloatField(this, 10, value);
};


/**
 * optional string cpu_arch = 11;
 * @return {string}
 */
proto.ScannedInfo.prototype.getCpuArch = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 11, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setCpuArch = function(value) {
  return jspb.Message.setProto3StringField(this, 11, value);
};


/**
 * optional string hypervisor = 12;
 * @return {string}
 */
proto.ScannedInfo.prototype.getHypervisor = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 12, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setHypervisor = function(value) {
  return jspb.Message.setProto3StringField(this, 12, value);
};


/**
 * optional string cpu_model = 13;
 * @return {string}
 */
proto.ScannedInfo.prototype.getCpuModel = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 13, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setCpuModel = function(value) {
  return jspb.Message.setProto3StringField(this, 13, value);
};


/**
 * optional double ram_size_gb = 14;
 * @return {number}
 */
proto.ScannedInfo.prototype.getRamSizeGb = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 14, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setRamSizeGb = function(value) {
  return jspb.Message.setProto3FloatField(this, 14, value);
};


/**
 * optional double ram_freq = 15;
 * @return {number}
 */
proto.ScannedInfo.prototype.getRamFreq = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 15, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setRamFreq = function(value) {
  return jspb.Message.setProto3FloatField(this, 15, value);
};


/**
 * optional int64 gpu = 16;
 * @return {number}
 */
proto.ScannedInfo.prototype.getGpu = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 16, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setGpu = function(value) {
  return jspb.Message.setProto3IntField(this, 16, value);
};


/**
 * optional string gpu_model = 17;
 * @return {string}
 */
proto.ScannedInfo.prototype.getGpuModel = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 17, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setGpuModel = function(value) {
  return jspb.Message.setProto3StringField(this, 17, value);
};


/**
 * optional int64 disk_size_gb = 18;
 * @return {number}
 */
proto.ScannedInfo.prototype.getDiskSizeGb = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 18, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setDiskSizeGb = function(value) {
  return jspb.Message.setProto3IntField(this, 18, value);
};


/**
 * optional string main_disk_type = 19;
 * @return {string}
 */
proto.ScannedInfo.prototype.getMainDiskType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 19, ""));
};


/**
 * @param {string} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setMainDiskType = function(value) {
  return jspb.Message.setProto3StringField(this, 19, value);
};


/**
 * optional double main_disk_speed_mbps = 20;
 * @return {number}
 */
proto.ScannedInfo.prototype.getMainDiskSpeedMbps = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 20, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setMainDiskSpeedMbps = function(value) {
  return jspb.Message.setProto3FloatField(this, 20, value);
};


/**
 * optional double sample_net_speed_kbps = 21;
 * @return {number}
 */
proto.ScannedInfo.prototype.getSampleNetSpeedKbps = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 21, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setSampleNetSpeedKbps = function(value) {
  return jspb.Message.setProto3FloatField(this, 21, value);
};


/**
 * optional int64 eph_disk_size_Gb = 22;
 * @return {number}
 */
proto.ScannedInfo.prototype.getEphDiskSizeGb = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 22, 0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setEphDiskSizeGb = function(value) {
  return jspb.Message.setProto3IntField(this, 22, value);
};


/**
 * optional double price_in_dollars_second = 23;
 * @return {number}
 */
proto.ScannedInfo.prototype.getPriceInDollarsSecond = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 23, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setPriceInDollarsSecond = function(value) {
  return jspb.Message.setProto3FloatField(this, 23, value);
};


/**
 * optional double price_in_dollars_hour = 24;
 * @return {number}
 */
proto.ScannedInfo.prototype.getPriceInDollarsHour = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 24, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.setPriceInDollarsHour = function(value) {
  return jspb.Message.setProto3FloatField(this, 24, value);
};


/**
 * repeated PriceInfo prices = 25;
 * @return {!Array<!proto.PriceInfo>}
 */
proto.ScannedInfo.prototype.getPricesList = function() {
  return /** @type{!Array<!proto.PriceInfo>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.PriceInfo, 25));
};


/**
 * @param {!Array<!proto.PriceInfo>} value
 * @return {!proto.ScannedInfo} returns this
*/
proto.ScannedInfo.prototype.setPricesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 25, value);
};


/**
 * @param {!proto.PriceInfo=} opt_value
 * @param {number=} opt_index
 * @return {!proto.PriceInfo}
 */
proto.ScannedInfo.prototype.addPrices = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 25, opt_value, proto.PriceInfo, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ScannedInfo} returns this
 */
proto.ScannedInfo.prototype.clearPricesList = function() {
  return this.setPricesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PriceInfo.prototype.toObject = function(opt_includeInstance) {
  return proto.PriceInfo.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PriceInfo} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PriceInfo.toObject = function(includeInstance, msg) {
  var f, obj = {
    currency: jspb.Message.getFieldWithDefault(msg, 1, ""),
    durationLabel: jspb.Message.getFieldWithDefault(msg, 2, ""),
    duration: jspb.Message.getFieldWithDefault(msg, 3, 0),
    price: jspb.Message.getFloatingPointFieldWithDefault(msg, 4, 0.0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PriceInfo}
 */
proto.PriceInfo.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PriceInfo;
  return proto.PriceInfo.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PriceInfo} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PriceInfo}
 */
proto.PriceInfo.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setCurrency(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setDurationLabel(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setDuration(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readDouble());
      msg.setPrice(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PriceInfo.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PriceInfo.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PriceInfo} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PriceInfo.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getCurrency();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getDurationLabel();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getDuration();
  if (f !== 0) {
    writer.writeUint32(
      3,
      f
    );
  }
  f = message.getPrice();
  if (f !== 0.0) {
    writer.writeDouble(
      4,
      f
    );
  }
};


/**
 * optional string currency = 1;
 * @return {string}
 */
proto.PriceInfo.prototype.getCurrency = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.PriceInfo} returns this
 */
proto.PriceInfo.prototype.setCurrency = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string duration_label = 2;
 * @return {string}
 */
proto.PriceInfo.prototype.getDurationLabel = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.PriceInfo} returns this
 */
proto.PriceInfo.prototype.setDurationLabel = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional uint32 duration = 3;
 * @return {number}
 */
proto.PriceInfo.prototype.getDuration = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {number} value
 * @return {!proto.PriceInfo} returns this
 */
proto.PriceInfo.prototype.setDuration = function(value) {
  return jspb.Message.setProto3IntField(this, 3, value);
};


/**
 * optional double price = 4;
 * @return {number}
 */
proto.PriceInfo.prototype.getPrice = function() {
  return /** @type {number} */ (jspb.Message.getFloatingPointFieldWithDefault(this, 4, 0.0));
};


/**
 * @param {number} value
 * @return {!proto.PriceInfo} returns this
 */
proto.PriceInfo.prototype.setPrice = function(value) {
  return jspb.Message.setProto3FloatField(this, 4, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.TemplateList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TemplateList.prototype.toObject = function(opt_includeInstance) {
  return proto.TemplateList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TemplateList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateList.toObject = function(includeInstance, msg) {
  var f, obj = {
    templatesList: jspb.Message.toObjectList(msg.getTemplatesList(),
    proto.HostTemplate.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TemplateList}
 */
proto.TemplateList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TemplateList;
  return proto.TemplateList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TemplateList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TemplateList}
 */
proto.TemplateList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.HostTemplate;
      reader.readMessage(value,proto.HostTemplate.deserializeBinaryFromReader);
      msg.addTemplates(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TemplateList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TemplateList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TemplateList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTemplatesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.HostTemplate.serializeBinaryToWriter
    );
  }
};


/**
 * repeated HostTemplate templates = 1;
 * @return {!Array<!proto.HostTemplate>}
 */
proto.TemplateList.prototype.getTemplatesList = function() {
  return /** @type{!Array<!proto.HostTemplate>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.HostTemplate, 1));
};


/**
 * @param {!Array<!proto.HostTemplate>} value
 * @return {!proto.TemplateList} returns this
*/
proto.TemplateList.prototype.setTemplatesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.HostTemplate=} opt_value
 * @param {number=} opt_index
 * @return {!proto.HostTemplate}
 */
proto.TemplateList.prototype.addTemplates = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.HostTemplate, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.TemplateList} returns this
 */
proto.TemplateList.prototype.clearTemplatesList = function() {
  return this.setTemplatesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TemplateListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TemplateListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TemplateListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, ""),
    scannedOnly: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TemplateListRequest}
 */
proto.TemplateListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TemplateListRequest;
  return proto.TemplateListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TemplateListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TemplateListRequest}
 */
proto.TemplateListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setScannedOnly(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TemplateListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TemplateListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TemplateListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getScannedOnly();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.TemplateListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TemplateListRequest} returns this
 */
proto.TemplateListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.TemplateListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TemplateListRequest} returns this
 */
proto.TemplateListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional bool scanned_only = 3;
 * @return {boolean}
 */
proto.TemplateListRequest.prototype.getScannedOnly = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.TemplateListRequest} returns this
 */
proto.TemplateListRequest.prototype.setScannedOnly = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TemplateMatchRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TemplateMatchRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TemplateMatchRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateMatchRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantId: jspb.Message.getFieldWithDefault(msg, 1, ""),
    sizing: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TemplateMatchRequest}
 */
proto.TemplateMatchRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TemplateMatchRequest;
  return proto.TemplateMatchRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TemplateMatchRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TemplateMatchRequest}
 */
proto.TemplateMatchRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setSizing(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TemplateMatchRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TemplateMatchRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TemplateMatchRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateMatchRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getSizing();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional string tenant_id = 1;
 * @return {string}
 */
proto.TemplateMatchRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.TemplateMatchRequest} returns this
 */
proto.TemplateMatchRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string sizing = 2;
 * @return {string}
 */
proto.TemplateMatchRequest.prototype.getSizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.TemplateMatchRequest} returns this
 */
proto.TemplateMatchRequest.prototype.setSizing = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.TemplateInspectRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.TemplateInspectRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.TemplateInspectRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateInspectRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    template: (f = msg.getTemplate()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.TemplateInspectRequest}
 */
proto.TemplateInspectRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.TemplateInspectRequest;
  return proto.TemplateInspectRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.TemplateInspectRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.TemplateInspectRequest}
 */
proto.TemplateInspectRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setTemplate(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.TemplateInspectRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.TemplateInspectRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.TemplateInspectRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.TemplateInspectRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTemplate();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference template = 1;
 * @return {?proto.Reference}
 */
proto.TemplateInspectRequest.prototype.getTemplate = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.TemplateInspectRequest} returns this
*/
proto.TemplateInspectRequest.prototype.setTemplate = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.TemplateInspectRequest} returns this
 */
proto.TemplateInspectRequest.prototype.clearTemplate = function() {
  return this.setTemplate(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.TemplateInspectRequest.prototype.hasTemplate = function() {
  return jspb.Message.getField(this, 1) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    speed: jspb.Message.getFieldWithDefault(msg, 3, 0),
    size: jspb.Message.getFieldWithDefault(msg, 4, 0),
    tenantId: jspb.Message.getFieldWithDefault(msg, 5, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeCreateRequest}
 */
proto.VolumeCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeCreateRequest;
  return proto.VolumeCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeCreateRequest}
 */
proto.VolumeCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {!proto.VolumeSpeed} */ (reader.readEnum());
      msg.setSpeed(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setSize(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getSpeed();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getSize();
  if (f !== 0) {
    writer.writeInt32(
      4,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.VolumeCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeCreateRequest} returns this
 */
proto.VolumeCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional VolumeSpeed speed = 3;
 * @return {!proto.VolumeSpeed}
 */
proto.VolumeCreateRequest.prototype.getSpeed = function() {
  return /** @type {!proto.VolumeSpeed} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.VolumeSpeed} value
 * @return {!proto.VolumeCreateRequest} returns this
 */
proto.VolumeCreateRequest.prototype.setSpeed = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional int32 size = 4;
 * @return {number}
 */
proto.VolumeCreateRequest.prototype.getSize = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {number} value
 * @return {!proto.VolumeCreateRequest} returns this
 */
proto.VolumeCreateRequest.prototype.setSize = function(value) {
  return jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional string tenant_id = 5;
 * @return {string}
 */
proto.VolumeCreateRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeCreateRequest} returns this
 */
proto.VolumeCreateRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeDetachmentRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeDetachmentRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeDetachmentRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeDetachmentRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    volume: (f = msg.getVolume()) && proto.Reference.toObject(includeInstance, f),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeDetachmentRequest}
 */
proto.VolumeDetachmentRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeDetachmentRequest;
  return proto.VolumeDetachmentRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeDetachmentRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeDetachmentRequest}
 */
proto.VolumeDetachmentRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setVolume(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeDetachmentRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeDetachmentRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeDetachmentRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeDetachmentRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getVolume();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference volume = 1;
 * @return {?proto.Reference}
 */
proto.VolumeDetachmentRequest.prototype.getVolume = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeDetachmentRequest} returns this
*/
proto.VolumeDetachmentRequest.prototype.setVolume = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeDetachmentRequest} returns this
 */
proto.VolumeDetachmentRequest.prototype.clearVolume = function() {
  return this.setVolume(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeDetachmentRequest.prototype.hasVolume = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.VolumeDetachmentRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeDetachmentRequest} returns this
*/
proto.VolumeDetachmentRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeDetachmentRequest} returns this
 */
proto.VolumeDetachmentRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeDetachmentRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.VolumeInspectResponse.repeatedFields_ = [10];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeInspectResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeInspectResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeInspectResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeInspectResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    speed: jspb.Message.getFieldWithDefault(msg, 3, 0),
    size: jspb.Message.getFieldWithDefault(msg, 4, 0),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    mountPath: jspb.Message.getFieldWithDefault(msg, 6, ""),
    format: jspb.Message.getFieldWithDefault(msg, 7, ""),
    device: jspb.Message.getFieldWithDefault(msg, 8, ""),
    attachmentsList: jspb.Message.toObjectList(msg.getAttachmentsList(),
    proto.VolumeAttachmentResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeInspectResponse}
 */
proto.VolumeInspectResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeInspectResponse;
  return proto.VolumeInspectResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeInspectResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeInspectResponse}
 */
proto.VolumeInspectResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {!proto.VolumeSpeed} */ (reader.readEnum());
      msg.setSpeed(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setSize(value);
      break;
    case 5:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setMountPath(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setFormat(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setDevice(value);
      break;
    case 10:
      var value = new proto.VolumeAttachmentResponse;
      reader.readMessage(value,proto.VolumeAttachmentResponse.deserializeBinaryFromReader);
      msg.addAttachments(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeInspectResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeInspectResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeInspectResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeInspectResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getSpeed();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getSize();
  if (f !== 0) {
    writer.writeInt32(
      4,
      f
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getMountPath();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getFormat();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getDevice();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getAttachmentsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      10,
      f,
      proto.VolumeAttachmentResponse.serializeBinaryToWriter
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.VolumeInspectResponse.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.VolumeInspectResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional VolumeSpeed speed = 3;
 * @return {!proto.VolumeSpeed}
 */
proto.VolumeInspectResponse.prototype.getSpeed = function() {
  return /** @type {!proto.VolumeSpeed} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.VolumeSpeed} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setSpeed = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional int32 size = 4;
 * @return {number}
 */
proto.VolumeInspectResponse.prototype.getSize = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {number} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setSize = function(value) {
  return jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional Reference host = 5;
 * @return {?proto.Reference}
 */
proto.VolumeInspectResponse.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 5));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeInspectResponse} returns this
*/
proto.VolumeInspectResponse.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeInspectResponse.prototype.hasHost = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional string mount_path = 6;
 * @return {string}
 */
proto.VolumeInspectResponse.prototype.getMountPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setMountPath = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string format = 7;
 * @return {string}
 */
proto.VolumeInspectResponse.prototype.getFormat = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setFormat = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string device = 8;
 * @return {string}
 */
proto.VolumeInspectResponse.prototype.getDevice = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.setDevice = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * repeated VolumeAttachmentResponse attachments = 10;
 * @return {!Array<!proto.VolumeAttachmentResponse>}
 */
proto.VolumeInspectResponse.prototype.getAttachmentsList = function() {
  return /** @type{!Array<!proto.VolumeAttachmentResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.VolumeAttachmentResponse, 10));
};


/**
 * @param {!Array<!proto.VolumeAttachmentResponse>} value
 * @return {!proto.VolumeInspectResponse} returns this
*/
proto.VolumeInspectResponse.prototype.setAttachmentsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 10, value);
};


/**
 * @param {!proto.VolumeAttachmentResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.VolumeAttachmentResponse}
 */
proto.VolumeInspectResponse.prototype.addAttachments = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 10, opt_value, proto.VolumeAttachmentResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.VolumeInspectResponse} returns this
 */
proto.VolumeInspectResponse.prototype.clearAttachmentsList = function() {
  return this.setAttachmentsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeAttachmentRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeAttachmentRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeAttachmentRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeAttachmentRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    volume: (f = msg.getVolume()) && proto.Reference.toObject(includeInstance, f),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    mountPath: jspb.Message.getFieldWithDefault(msg, 4, ""),
    format: jspb.Message.getFieldWithDefault(msg, 5, ""),
    device: jspb.Message.getFieldWithDefault(msg, 6, ""),
    doNotFormat: jspb.Message.getBooleanFieldWithDefault(msg, 7, false),
    doNotMount: jspb.Message.getBooleanFieldWithDefault(msg, 8, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeAttachmentRequest}
 */
proto.VolumeAttachmentRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeAttachmentRequest;
  return proto.VolumeAttachmentRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeAttachmentRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeAttachmentRequest}
 */
proto.VolumeAttachmentRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setVolume(value);
      break;
    case 3:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setMountPath(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setFormat(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setDevice(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDoNotFormat(value);
      break;
    case 8:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDoNotMount(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeAttachmentRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeAttachmentRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeAttachmentRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeAttachmentRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getVolume();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getMountPath();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getFormat();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getDevice();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getDoNotFormat();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
  f = message.getDoNotMount();
  if (f) {
    writer.writeBool(
      8,
      f
    );
  }
};


/**
 * optional Reference volume = 2;
 * @return {?proto.Reference}
 */
proto.VolumeAttachmentRequest.prototype.getVolume = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeAttachmentRequest} returns this
*/
proto.VolumeAttachmentRequest.prototype.setVolume = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.clearVolume = function() {
  return this.setVolume(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeAttachmentRequest.prototype.hasVolume = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional Reference host = 3;
 * @return {?proto.Reference}
 */
proto.VolumeAttachmentRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 3));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeAttachmentRequest} returns this
*/
proto.VolumeAttachmentRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeAttachmentRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 3) != null;
};


/**
 * optional string mount_path = 4;
 * @return {string}
 */
proto.VolumeAttachmentRequest.prototype.getMountPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.setMountPath = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string format = 5;
 * @return {string}
 */
proto.VolumeAttachmentRequest.prototype.getFormat = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.setFormat = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string device = 6;
 * @return {string}
 */
proto.VolumeAttachmentRequest.prototype.getDevice = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.setDevice = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional bool do_not_format = 7;
 * @return {boolean}
 */
proto.VolumeAttachmentRequest.prototype.getDoNotFormat = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.setDoNotFormat = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};


/**
 * optional bool do_not_mount = 8;
 * @return {boolean}
 */
proto.VolumeAttachmentRequest.prototype.getDoNotMount = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 8, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeAttachmentRequest} returns this
 */
proto.VolumeAttachmentRequest.prototype.setDoNotMount = function(value) {
  return jspb.Message.setProto3BooleanField(this, 8, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeAttachmentResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeAttachmentResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeAttachmentResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeAttachmentResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    mountPath: jspb.Message.getFieldWithDefault(msg, 2, ""),
    format: jspb.Message.getFieldWithDefault(msg, 3, ""),
    device: jspb.Message.getFieldWithDefault(msg, 4, ""),
    doNotFormat: jspb.Message.getBooleanFieldWithDefault(msg, 5, false),
    mount: jspb.Message.getBooleanFieldWithDefault(msg, 6, false),
    formatted: jspb.Message.getBooleanFieldWithDefault(msg, 7, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeAttachmentResponse}
 */
proto.VolumeAttachmentResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeAttachmentResponse;
  return proto.VolumeAttachmentResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeAttachmentResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeAttachmentResponse}
 */
proto.VolumeAttachmentResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setMountPath(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setFormat(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setDevice(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDoNotFormat(value);
      break;
    case 6:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setMount(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setFormatted(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeAttachmentResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeAttachmentResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeAttachmentResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeAttachmentResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getMountPath();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getFormat();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getDevice();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getDoNotFormat();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
  f = message.getMount();
  if (f) {
    writer.writeBool(
      6,
      f
    );
  }
  f = message.getFormatted();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.VolumeAttachmentResponse.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.VolumeAttachmentResponse} returns this
*/
proto.VolumeAttachmentResponse.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.VolumeAttachmentResponse.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string mount_path = 2;
 * @return {string}
 */
proto.VolumeAttachmentResponse.prototype.getMountPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setMountPath = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string format = 3;
 * @return {string}
 */
proto.VolumeAttachmentResponse.prototype.getFormat = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setFormat = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string device = 4;
 * @return {string}
 */
proto.VolumeAttachmentResponse.prototype.getDevice = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setDevice = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional bool do_not_format = 5;
 * @return {boolean}
 */
proto.VolumeAttachmentResponse.prototype.getDoNotFormat = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setDoNotFormat = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};


/**
 * optional bool mount = 6;
 * @return {boolean}
 */
proto.VolumeAttachmentResponse.prototype.getMount = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 6, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setMount = function(value) {
  return jspb.Message.setProto3BooleanField(this, 6, value);
};


/**
 * optional bool formatted = 7;
 * @return {boolean}
 */
proto.VolumeAttachmentResponse.prototype.getFormatted = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeAttachmentResponse} returns this
 */
proto.VolumeAttachmentResponse.prototype.setFormatted = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeListRequest}
 */
proto.VolumeListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeListRequest;
  return proto.VolumeListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeListRequest}
 */
proto.VolumeListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.VolumeListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.VolumeListRequest} returns this
 */
proto.VolumeListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.VolumeListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.VolumeListRequest} returns this
 */
proto.VolumeListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.VolumeListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.VolumeListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.VolumeListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.VolumeListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    volumesList: jspb.Message.toObjectList(msg.getVolumesList(),
    proto.VolumeInspectResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.VolumeListResponse}
 */
proto.VolumeListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.VolumeListResponse;
  return proto.VolumeListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.VolumeListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.VolumeListResponse}
 */
proto.VolumeListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.VolumeInspectResponse;
      reader.readMessage(value,proto.VolumeInspectResponse.deserializeBinaryFromReader);
      msg.addVolumes(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.VolumeListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.VolumeListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.VolumeListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.VolumeListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getVolumesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.VolumeInspectResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated VolumeInspectResponse volumes = 1;
 * @return {!Array<!proto.VolumeInspectResponse>}
 */
proto.VolumeListResponse.prototype.getVolumesList = function() {
  return /** @type{!Array<!proto.VolumeInspectResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.VolumeInspectResponse, 1));
};


/**
 * @param {!Array<!proto.VolumeInspectResponse>} value
 * @return {!proto.VolumeListResponse} returns this
*/
proto.VolumeListResponse.prototype.setVolumesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.VolumeInspectResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.VolumeInspectResponse}
 */
proto.VolumeListResponse.prototype.addVolumes = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.VolumeInspectResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.VolumeListResponse} returns this
 */
proto.VolumeListResponse.prototype.clearVolumesList = function() {
  return this.setVolumesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketMount.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketMount.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketMount} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketMount.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    path: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketMount}
 */
proto.BucketMount.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketMount;
  return proto.BucketMount.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketMount} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketMount}
 */
proto.BucketMount.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setPath(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketMount.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketMount.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketMount} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketMount.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getPath();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.BucketMount.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.BucketMount} returns this
*/
proto.BucketMount.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.BucketMount} returns this
 */
proto.BucketMount.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.BucketMount.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string path = 2;
 * @return {string}
 */
proto.BucketMount.prototype.getPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.BucketMount} returns this
 */
proto.BucketMount.prototype.setPath = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketRequest}
 */
proto.BucketRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketRequest;
  return proto.BucketRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketRequest}
 */
proto.BucketRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.BucketRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.BucketRequest} returns this
 */
proto.BucketRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.BucketResponse.repeatedFields_ = [2];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    mountsList: jspb.Message.toObjectList(msg.getMountsList(),
    proto.BucketMount.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketResponse}
 */
proto.BucketResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketResponse;
  return proto.BucketResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketResponse}
 */
proto.BucketResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = new proto.BucketMount;
      reader.readMessage(value,proto.BucketMount.deserializeBinaryFromReader);
      msg.addMounts(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getMountsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      2,
      f,
      proto.BucketMount.serializeBinaryToWriter
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.BucketResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.BucketResponse} returns this
 */
proto.BucketResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * repeated BucketMount mounts = 2;
 * @return {!Array<!proto.BucketMount>}
 */
proto.BucketResponse.prototype.getMountsList = function() {
  return /** @type{!Array<!proto.BucketMount>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.BucketMount, 2));
};


/**
 * @param {!Array<!proto.BucketMount>} value
 * @return {!proto.BucketResponse} returns this
*/
proto.BucketResponse.prototype.setMountsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 2, value);
};


/**
 * @param {!proto.BucketMount=} opt_value
 * @param {number=} opt_index
 * @return {!proto.BucketMount}
 */
proto.BucketResponse.prototype.addMounts = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 2, opt_value, proto.BucketMount, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.BucketResponse} returns this
 */
proto.BucketResponse.prototype.clearMountsList = function() {
  return this.setMountsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketListRequest}
 */
proto.BucketListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketListRequest;
  return proto.BucketListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketListRequest}
 */
proto.BucketListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.BucketListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.BucketListRequest} returns this
 */
proto.BucketListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.BucketListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    bucketsList: jspb.Message.toObjectList(msg.getBucketsList(),
    proto.BucketResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketListResponse}
 */
proto.BucketListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketListResponse;
  return proto.BucketListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketListResponse}
 */
proto.BucketListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.BucketResponse;
      reader.readMessage(value,proto.BucketResponse.deserializeBinaryFromReader);
      msg.addBuckets(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getBucketsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.BucketResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated BucketResponse buckets = 1;
 * @return {!Array<!proto.BucketResponse>}
 */
proto.BucketListResponse.prototype.getBucketsList = function() {
  return /** @type{!Array<!proto.BucketResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.BucketResponse, 1));
};


/**
 * @param {!Array<!proto.BucketResponse>} value
 * @return {!proto.BucketListResponse} returns this
*/
proto.BucketListResponse.prototype.setBucketsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.BucketResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.BucketResponse}
 */
proto.BucketListResponse.prototype.addBuckets = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.BucketResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.BucketListResponse} returns this
 */
proto.BucketListResponse.prototype.clearBucketsList = function() {
  return this.setBucketsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketDownloadResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketDownloadResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketDownloadResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketDownloadResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    content: msg.getContent_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketDownloadResponse}
 */
proto.BucketDownloadResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketDownloadResponse;
  return proto.BucketDownloadResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketDownloadResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketDownloadResponse}
 */
proto.BucketDownloadResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setContent(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketDownloadResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketDownloadResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketDownloadResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketDownloadResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getContent_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      1,
      f
    );
  }
};


/**
 * optional bytes content = 1;
 * @return {!(string|Uint8Array)}
 */
proto.BucketDownloadResponse.prototype.getContent = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * optional bytes content = 1;
 * This is a type-conversion wrapper around `getContent()`
 * @return {string}
 */
proto.BucketDownloadResponse.prototype.getContent_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getContent()));
};


/**
 * optional bytes content = 1;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getContent()`
 * @return {!Uint8Array}
 */
proto.BucketDownloadResponse.prototype.getContent_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getContent()));
};


/**
 * @param {!(string|Uint8Array)} value
 * @return {!proto.BucketDownloadResponse} returns this
 */
proto.BucketDownloadResponse.prototype.setContent = function(value) {
  return jspb.Message.setProto3BytesField(this, 1, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.BucketMountRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.BucketMountRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.BucketMountRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketMountRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    bucket: jspb.Message.getFieldWithDefault(msg, 1, ""),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    path: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.BucketMountRequest}
 */
proto.BucketMountRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.BucketMountRequest;
  return proto.BucketMountRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.BucketMountRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.BucketMountRequest}
 */
proto.BucketMountRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setBucket(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setPath(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.BucketMountRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.BucketMountRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.BucketMountRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.BucketMountRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getBucket();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getPath();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string bucket = 1;
 * @return {string}
 */
proto.BucketMountRequest.prototype.getBucket = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.BucketMountRequest} returns this
 */
proto.BucketMountRequest.prototype.setBucket = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.BucketMountRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.BucketMountRequest} returns this
*/
proto.BucketMountRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.BucketMountRequest} returns this
 */
proto.BucketMountRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.BucketMountRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional string path = 3;
 * @return {string}
 */
proto.BucketMountRequest.prototype.getPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.BucketMountRequest} returns this
 */
proto.BucketMountRequest.prototype.setPath = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SshCommand.prototype.toObject = function(opt_includeInstance) {
  return proto.SshCommand.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SshCommand} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshCommand.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    command: jspb.Message.getFieldWithDefault(msg, 2, ""),
    tenantId: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SshCommand}
 */
proto.SshCommand.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SshCommand;
  return proto.SshCommand.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SshCommand} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SshCommand}
 */
proto.SshCommand.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setCommand(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SshCommand.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SshCommand.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SshCommand} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshCommand.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getCommand();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.SshCommand.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SshCommand} returns this
*/
proto.SshCommand.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SshCommand} returns this
 */
proto.SshCommand.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SshCommand.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string command = 2;
 * @return {string}
 */
proto.SshCommand.prototype.getCommand = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCommand} returns this
 */
proto.SshCommand.prototype.setCommand = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string tenant_id = 3;
 * @return {string}
 */
proto.SshCommand.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCommand} returns this
 */
proto.SshCommand.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SshCopyCommand.prototype.toObject = function(opt_includeInstance) {
  return proto.SshCopyCommand.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SshCopyCommand} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshCopyCommand.toObject = function(includeInstance, msg) {
  var f, obj = {
    source: jspb.Message.getFieldWithDefault(msg, 1, ""),
    destination: jspb.Message.getFieldWithDefault(msg, 2, ""),
    owner: jspb.Message.getFieldWithDefault(msg, 3, ""),
    mode: jspb.Message.getFieldWithDefault(msg, 4, ""),
    tenantId: jspb.Message.getFieldWithDefault(msg, 5, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SshCopyCommand}
 */
proto.SshCopyCommand.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SshCopyCommand;
  return proto.SshCopyCommand.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SshCopyCommand} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SshCopyCommand}
 */
proto.SshCopyCommand.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setSource(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setDestination(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setOwner(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setMode(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SshCopyCommand.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SshCopyCommand.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SshCopyCommand} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshCopyCommand.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSource();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getDestination();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getOwner();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getMode();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
};


/**
 * optional string source = 1;
 * @return {string}
 */
proto.SshCopyCommand.prototype.getSource = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCopyCommand} returns this
 */
proto.SshCopyCommand.prototype.setSource = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string destination = 2;
 * @return {string}
 */
proto.SshCopyCommand.prototype.getDestination = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCopyCommand} returns this
 */
proto.SshCopyCommand.prototype.setDestination = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string owner = 3;
 * @return {string}
 */
proto.SshCopyCommand.prototype.getOwner = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCopyCommand} returns this
 */
proto.SshCopyCommand.prototype.setOwner = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string mode = 4;
 * @return {string}
 */
proto.SshCopyCommand.prototype.getMode = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCopyCommand} returns this
 */
proto.SshCopyCommand.prototype.setMode = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string tenant_id = 5;
 * @return {string}
 */
proto.SshCopyCommand.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshCopyCommand} returns this
 */
proto.SshCopyCommand.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SshResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.SshResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SshResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    outputStd: jspb.Message.getFieldWithDefault(msg, 1, ""),
    outputErr: jspb.Message.getFieldWithDefault(msg, 2, ""),
    status: jspb.Message.getFieldWithDefault(msg, 3, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SshResponse}
 */
proto.SshResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SshResponse;
  return proto.SshResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SshResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SshResponse}
 */
proto.SshResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setOutputStd(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setOutputErr(value);
      break;
    case 3:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setStatus(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SshResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SshResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SshResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SshResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getOutputStd();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getOutputErr();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getStatus();
  if (f !== 0) {
    writer.writeInt32(
      3,
      f
    );
  }
};


/**
 * optional string output_std = 1;
 * @return {string}
 */
proto.SshResponse.prototype.getOutputStd = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshResponse} returns this
 */
proto.SshResponse.prototype.setOutputStd = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string output_err = 2;
 * @return {string}
 */
proto.SshResponse.prototype.getOutputErr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SshResponse} returns this
 */
proto.SshResponse.prototype.setOutputErr = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional int32 status = 3;
 * @return {number}
 */
proto.SshResponse.prototype.getStatus = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {number} value
 * @return {!proto.SshResponse} returns this
 */
proto.SshResponse.prototype.setStatus = function(value) {
  return jspb.Message.setProto3IntField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.NFSExportOptions.prototype.toObject = function(opt_includeInstance) {
  return proto.NFSExportOptions.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.NFSExportOptions} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NFSExportOptions.toObject = function(includeInstance, msg) {
  var f, obj = {
    readOnly: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    rootSquash: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    secure: jspb.Message.getBooleanFieldWithDefault(msg, 3, false),
    async: jspb.Message.getBooleanFieldWithDefault(msg, 4, false),
    noHide: jspb.Message.getBooleanFieldWithDefault(msg, 5, false),
    crossMount: jspb.Message.getBooleanFieldWithDefault(msg, 6, false),
    subtreeCheck: jspb.Message.getBooleanFieldWithDefault(msg, 7, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.NFSExportOptions}
 */
proto.NFSExportOptions.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.NFSExportOptions;
  return proto.NFSExportOptions.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.NFSExportOptions} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.NFSExportOptions}
 */
proto.NFSExportOptions.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setReadOnly(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setRootSquash(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setSecure(value);
      break;
    case 4:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAsync(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setNoHide(value);
      break;
    case 6:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setCrossMount(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setSubtreeCheck(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.NFSExportOptions.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.NFSExportOptions.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.NFSExportOptions} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.NFSExportOptions.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getReadOnly();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getRootSquash();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getSecure();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
  f = message.getAsync();
  if (f) {
    writer.writeBool(
      4,
      f
    );
  }
  f = message.getNoHide();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
  f = message.getCrossMount();
  if (f) {
    writer.writeBool(
      6,
      f
    );
  }
  f = message.getSubtreeCheck();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
};


/**
 * optional bool read_only = 1;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getReadOnly = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setReadOnly = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional bool root_squash = 2;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getRootSquash = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setRootSquash = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * optional bool secure = 3;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getSecure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setSecure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};


/**
 * optional bool async = 4;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getAsync = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 4, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setAsync = function(value) {
  return jspb.Message.setProto3BooleanField(this, 4, value);
};


/**
 * optional bool no_hide = 5;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getNoHide = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setNoHide = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};


/**
 * optional bool cross_mount = 6;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getCrossMount = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 6, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setCrossMount = function(value) {
  return jspb.Message.setProto3BooleanField(this, 6, value);
};


/**
 * optional bool subtree_check = 7;
 * @return {boolean}
 */
proto.NFSExportOptions.prototype.getSubtreeCheck = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.NFSExportOptions} returns this
 */
proto.NFSExportOptions.prototype.setSubtreeCheck = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ShareDefinition.repeatedFields_ = [7];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ShareDefinition.prototype.toObject = function(opt_includeInstance) {
  return proto.ShareDefinition.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ShareDefinition} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareDefinition.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    path: jspb.Message.getFieldWithDefault(msg, 4, ""),
    type: jspb.Message.getFieldWithDefault(msg, 5, ""),
    options: (f = msg.getOptions()) && proto.NFSExportOptions.toObject(includeInstance, f),
    securityModesList: (f = jspb.Message.getRepeatedField(msg, 7)) == null ? undefined : f,
    optionsAsString: jspb.Message.getFieldWithDefault(msg, 8, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ShareDefinition}
 */
proto.ShareDefinition.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ShareDefinition;
  return proto.ShareDefinition.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ShareDefinition} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ShareDefinition}
 */
proto.ShareDefinition.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setPath(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setType(value);
      break;
    case 6:
      var value = new proto.NFSExportOptions;
      reader.readMessage(value,proto.NFSExportOptions.deserializeBinaryFromReader);
      msg.setOptions(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.addSecurityModes(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setOptionsAsString(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ShareDefinition.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ShareDefinition.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ShareDefinition} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareDefinition.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getPath();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getType();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getOptions();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.NFSExportOptions.serializeBinaryToWriter
    );
  }
  f = message.getSecurityModesList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      7,
      f
    );
  }
  f = message.getOptionsAsString();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.ShareDefinition.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.ShareDefinition.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional Reference host = 3;
 * @return {?proto.Reference}
 */
proto.ShareDefinition.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 3));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.ShareDefinition} returns this
*/
proto.ShareDefinition.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ShareDefinition.prototype.hasHost = function() {
  return jspb.Message.getField(this, 3) != null;
};


/**
 * optional string path = 4;
 * @return {string}
 */
proto.ShareDefinition.prototype.getPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setPath = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string type = 5;
 * @return {string}
 */
proto.ShareDefinition.prototype.getType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setType = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional NFSExportOptions options = 6;
 * @return {?proto.NFSExportOptions}
 */
proto.ShareDefinition.prototype.getOptions = function() {
  return /** @type{?proto.NFSExportOptions} */ (
    jspb.Message.getWrapperField(this, proto.NFSExportOptions, 6));
};


/**
 * @param {?proto.NFSExportOptions|undefined} value
 * @return {!proto.ShareDefinition} returns this
*/
proto.ShareDefinition.prototype.setOptions = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.clearOptions = function() {
  return this.setOptions(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ShareDefinition.prototype.hasOptions = function() {
  return jspb.Message.getField(this, 6) != null;
};


/**
 * repeated string security_modes = 7;
 * @return {!Array<string>}
 */
proto.ShareDefinition.prototype.getSecurityModesList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 7));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setSecurityModesList = function(value) {
  return jspb.Message.setField(this, 7, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.addSecurityModes = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 7, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.clearSecurityModesList = function() {
  return this.setSecurityModesList([]);
};


/**
 * optional string options_as_string = 8;
 * @return {string}
 */
proto.ShareDefinition.prototype.getOptionsAsString = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareDefinition} returns this
 */
proto.ShareDefinition.prototype.setOptionsAsString = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ShareList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ShareList.prototype.toObject = function(opt_includeInstance) {
  return proto.ShareList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ShareList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareList.toObject = function(includeInstance, msg) {
  var f, obj = {
    shareListList: jspb.Message.toObjectList(msg.getShareListList(),
    proto.ShareDefinition.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ShareList}
 */
proto.ShareList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ShareList;
  return proto.ShareList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ShareList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ShareList}
 */
proto.ShareList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ShareDefinition;
      reader.readMessage(value,proto.ShareDefinition.deserializeBinaryFromReader);
      msg.addShareList(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ShareList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ShareList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ShareList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getShareListList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.ShareDefinition.serializeBinaryToWriter
    );
  }
};


/**
 * repeated ShareDefinition share_list = 1;
 * @return {!Array<!proto.ShareDefinition>}
 */
proto.ShareList.prototype.getShareListList = function() {
  return /** @type{!Array<!proto.ShareDefinition>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.ShareDefinition, 1));
};


/**
 * @param {!Array<!proto.ShareDefinition>} value
 * @return {!proto.ShareList} returns this
*/
proto.ShareList.prototype.setShareListList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.ShareDefinition=} opt_value
 * @param {number=} opt_index
 * @return {!proto.ShareDefinition}
 */
proto.ShareList.prototype.addShareList = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.ShareDefinition, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ShareList} returns this
 */
proto.ShareList.prototype.clearShareListList = function() {
  return this.setShareListList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ShareMountDefinition.prototype.toObject = function(opt_includeInstance) {
  return proto.ShareMountDefinition.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ShareMountDefinition} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareMountDefinition.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    share: (f = msg.getShare()) && proto.Reference.toObject(includeInstance, f),
    path: jspb.Message.getFieldWithDefault(msg, 3, ""),
    type: jspb.Message.getFieldWithDefault(msg, 4, ""),
    options: jspb.Message.getFieldWithDefault(msg, 5, ""),
    withCache: jspb.Message.getBooleanFieldWithDefault(msg, 6, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ShareMountDefinition}
 */
proto.ShareMountDefinition.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ShareMountDefinition;
  return proto.ShareMountDefinition.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ShareMountDefinition} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ShareMountDefinition}
 */
proto.ShareMountDefinition.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setShare(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setPath(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setType(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setOptions(value);
      break;
    case 6:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setWithCache(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ShareMountDefinition.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ShareMountDefinition.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ShareMountDefinition} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareMountDefinition.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getShare();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getPath();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getType();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getOptions();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getWithCache();
  if (f) {
    writer.writeBool(
      6,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.ShareMountDefinition.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.ShareMountDefinition} returns this
*/
proto.ShareMountDefinition.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ShareMountDefinition.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference share = 2;
 * @return {?proto.Reference}
 */
proto.ShareMountDefinition.prototype.getShare = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.ShareMountDefinition} returns this
*/
proto.ShareMountDefinition.prototype.setShare = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.clearShare = function() {
  return this.setShare(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ShareMountDefinition.prototype.hasShare = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional string path = 3;
 * @return {string}
 */
proto.ShareMountDefinition.prototype.getPath = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.setPath = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string type = 4;
 * @return {string}
 */
proto.ShareMountDefinition.prototype.getType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.setType = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string options = 5;
 * @return {string}
 */
proto.ShareMountDefinition.prototype.getOptions = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.setOptions = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional bool with_cache = 6;
 * @return {boolean}
 */
proto.ShareMountDefinition.prototype.getWithCache = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 6, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ShareMountDefinition} returns this
 */
proto.ShareMountDefinition.prototype.setWithCache = function(value) {
  return jspb.Message.setProto3BooleanField(this, 6, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ShareMountList.repeatedFields_ = [2];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ShareMountList.prototype.toObject = function(opt_includeInstance) {
  return proto.ShareMountList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ShareMountList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareMountList.toObject = function(includeInstance, msg) {
  var f, obj = {
    share: (f = msg.getShare()) && proto.ShareDefinition.toObject(includeInstance, f),
    mountListList: jspb.Message.toObjectList(msg.getMountListList(),
    proto.ShareMountDefinition.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ShareMountList}
 */
proto.ShareMountList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ShareMountList;
  return proto.ShareMountList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ShareMountList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ShareMountList}
 */
proto.ShareMountList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ShareDefinition;
      reader.readMessage(value,proto.ShareDefinition.deserializeBinaryFromReader);
      msg.setShare(value);
      break;
    case 2:
      var value = new proto.ShareMountDefinition;
      reader.readMessage(value,proto.ShareMountDefinition.deserializeBinaryFromReader);
      msg.addMountList(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ShareMountList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ShareMountList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ShareMountList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ShareMountList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getShare();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.ShareDefinition.serializeBinaryToWriter
    );
  }
  f = message.getMountListList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      2,
      f,
      proto.ShareMountDefinition.serializeBinaryToWriter
    );
  }
};


/**
 * optional ShareDefinition share = 1;
 * @return {?proto.ShareDefinition}
 */
proto.ShareMountList.prototype.getShare = function() {
  return /** @type{?proto.ShareDefinition} */ (
    jspb.Message.getWrapperField(this, proto.ShareDefinition, 1));
};


/**
 * @param {?proto.ShareDefinition|undefined} value
 * @return {!proto.ShareMountList} returns this
*/
proto.ShareMountList.prototype.setShare = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ShareMountList} returns this
 */
proto.ShareMountList.prototype.clearShare = function() {
  return this.setShare(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ShareMountList.prototype.hasShare = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * repeated ShareMountDefinition mount_list = 2;
 * @return {!Array<!proto.ShareMountDefinition>}
 */
proto.ShareMountList.prototype.getMountListList = function() {
  return /** @type{!Array<!proto.ShareMountDefinition>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.ShareMountDefinition, 2));
};


/**
 * @param {!Array<!proto.ShareMountDefinition>} value
 * @return {!proto.ShareMountList} returns this
*/
proto.ShareMountList.prototype.setMountListList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 2, value);
};


/**
 * @param {!proto.ShareMountDefinition=} opt_value
 * @param {number=} opt_index
 * @return {!proto.ShareMountDefinition}
 */
proto.ShareMountList.prototype.addMountList = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 2, opt_value, proto.ShareMountDefinition, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ShareMountList} returns this
 */
proto.ShareMountList.prototype.clearMountListList = function() {
  return this.setMountListList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.JobDefinition.prototype.toObject = function(opt_includeInstance) {
  return proto.JobDefinition.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.JobDefinition} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.JobDefinition.toObject = function(includeInstance, msg) {
  var f, obj = {
    uuid: jspb.Message.getFieldWithDefault(msg, 1, ""),
    info: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.JobDefinition}
 */
proto.JobDefinition.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.JobDefinition;
  return proto.JobDefinition.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.JobDefinition} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.JobDefinition}
 */
proto.JobDefinition.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setUuid(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setInfo(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.JobDefinition.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.JobDefinition.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.JobDefinition} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.JobDefinition.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getUuid();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getInfo();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional string uuid = 1;
 * @return {string}
 */
proto.JobDefinition.prototype.getUuid = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.JobDefinition} returns this
 */
proto.JobDefinition.prototype.setUuid = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string info = 2;
 * @return {string}
 */
proto.JobDefinition.prototype.getInfo = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.JobDefinition} returns this
 */
proto.JobDefinition.prototype.setInfo = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.JobList.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.JobList.prototype.toObject = function(opt_includeInstance) {
  return proto.JobList.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.JobList} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.JobList.toObject = function(includeInstance, msg) {
  var f, obj = {
    listList: jspb.Message.toObjectList(msg.getListList(),
    proto.JobDefinition.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.JobList}
 */
proto.JobList.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.JobList;
  return proto.JobList.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.JobList} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.JobList}
 */
proto.JobList.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.JobDefinition;
      reader.readMessage(value,proto.JobDefinition.deserializeBinaryFromReader);
      msg.addList(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.JobList.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.JobList.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.JobList} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.JobList.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getListList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.JobDefinition.serializeBinaryToWriter
    );
  }
};


/**
 * repeated JobDefinition list = 1;
 * @return {!Array<!proto.JobDefinition>}
 */
proto.JobList.prototype.getListList = function() {
  return /** @type{!Array<!proto.JobDefinition>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.JobDefinition, 1));
};


/**
 * @param {!Array<!proto.JobDefinition>} value
 * @return {!proto.JobList} returns this
*/
proto.JobList.prototype.setListList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.JobDefinition=} opt_value
 * @param {number=} opt_index
 * @return {!proto.JobDefinition}
 */
proto.JobList.prototype.addList = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.JobDefinition, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.JobList} returns this
 */
proto.JobList.prototype.clearListList = function() {
  return this.setListList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterStateResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterStateResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterStateResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterStateResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    state: jspb.Message.getFieldWithDefault(msg, 1, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterStateResponse}
 */
proto.ClusterStateResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterStateResponse;
  return proto.ClusterStateResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterStateResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterStateResponse}
 */
proto.ClusterStateResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!proto.ClusterState} */ (reader.readEnum());
      msg.setState(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterStateResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterStateResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterStateResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterStateResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      1,
      f
    );
  }
};


/**
 * optional ClusterState state = 1;
 * @return {!proto.ClusterState}
 */
proto.ClusterStateResponse.prototype.getState = function() {
  return /** @type {!proto.ClusterState} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {!proto.ClusterState} value
 * @return {!proto.ClusterStateResponse} returns this
 */
proto.ClusterStateResponse.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 1, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    clustersList: jspb.Message.toObjectList(msg.getClustersList(),
    proto.ClusterResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterListResponse}
 */
proto.ClusterListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterListResponse;
  return proto.ClusterListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterListResponse}
 */
proto.ClusterListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ClusterResponse;
      reader.readMessage(value,proto.ClusterResponse.deserializeBinaryFromReader);
      msg.addClusters(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getClustersList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.ClusterResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated ClusterResponse clusters = 1;
 * @return {!Array<!proto.ClusterResponse>}
 */
proto.ClusterListResponse.prototype.getClustersList = function() {
  return /** @type{!Array<!proto.ClusterResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.ClusterResponse, 1));
};


/**
 * @param {!Array<!proto.ClusterResponse>} value
 * @return {!proto.ClusterListResponse} returns this
*/
proto.ClusterListResponse.prototype.setClustersList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.ClusterResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.ClusterResponse}
 */
proto.ClusterListResponse.prototype.addClusters = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.ClusterResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterListResponse} returns this
 */
proto.ClusterListResponse.prototype.clearClustersList = function() {
  return this.setClustersList([]);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterCreateRequest.repeatedFields_ = [6,18];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    complexity: jspb.Message.getFieldWithDefault(msg, 2, 0),
    flavor: jspb.Message.getFieldWithDefault(msg, 3, 0),
    keepOnFailure: jspb.Message.getBooleanFieldWithDefault(msg, 4, false),
    cidr: jspb.Message.getFieldWithDefault(msg, 5, ""),
    disabledList: (f = jspb.Message.getRepeatedField(msg, 6)) == null ? undefined : f,
    os: jspb.Message.getFieldWithDefault(msg, 7, ""),
    globalSizing: jspb.Message.getFieldWithDefault(msg, 8, ""),
    gatewaySizing: jspb.Message.getFieldWithDefault(msg, 9, ""),
    masterSizing: jspb.Message.getFieldWithDefault(msg, 10, ""),
    nodeSizing: jspb.Message.getFieldWithDefault(msg, 11, ""),
    domain: jspb.Message.getFieldWithDefault(msg, 12, ""),
    tenantId: jspb.Message.getFieldWithDefault(msg, 13, ""),
    gatewayOptions: jspb.Message.getFieldWithDefault(msg, 14, ""),
    masterOptions: jspb.Message.getFieldWithDefault(msg, 15, ""),
    nodeOptions: jspb.Message.getFieldWithDefault(msg, 16, ""),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 17, false),
    parametersList: (f = jspb.Message.getRepeatedField(msg, 18)) == null ? undefined : f,
    defaultSshPort: jspb.Message.getFieldWithDefault(msg, 19, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterCreateRequest}
 */
proto.ClusterCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterCreateRequest;
  return proto.ClusterCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterCreateRequest}
 */
proto.ClusterCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {!proto.ClusterComplexity} */ (reader.readEnum());
      msg.setComplexity(value);
      break;
    case 3:
      var value = /** @type {!proto.ClusterFlavor} */ (reader.readEnum());
      msg.setFlavor(value);
      break;
    case 4:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setKeepOnFailure(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.addDisabled(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setOs(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setGlobalSizing(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewaySizing(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.setMasterSizing(value);
      break;
    case 11:
      var value = /** @type {string} */ (reader.readString());
      msg.setNodeSizing(value);
      break;
    case 12:
      var value = /** @type {string} */ (reader.readString());
      msg.setDomain(value);
      break;
    case 13:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 14:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewayOptions(value);
      break;
    case 15:
      var value = /** @type {string} */ (reader.readString());
      msg.setMasterOptions(value);
      break;
    case 16:
      var value = /** @type {string} */ (reader.readString());
      msg.setNodeOptions(value);
      break;
    case 17:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    case 18:
      var value = /** @type {string} */ (reader.readString());
      msg.addParameters(value);
      break;
    case 19:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setDefaultSshPort(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getComplexity();
  if (f !== 0.0) {
    writer.writeEnum(
      2,
      f
    );
  }
  f = message.getFlavor();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getKeepOnFailure();
  if (f) {
    writer.writeBool(
      4,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getDisabledList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      6,
      f
    );
  }
  f = message.getOs();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getGlobalSizing();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getGatewaySizing();
  if (f.length > 0) {
    writer.writeString(
      9,
      f
    );
  }
  f = message.getMasterSizing();
  if (f.length > 0) {
    writer.writeString(
      10,
      f
    );
  }
  f = message.getNodeSizing();
  if (f.length > 0) {
    writer.writeString(
      11,
      f
    );
  }
  f = message.getDomain();
  if (f.length > 0) {
    writer.writeString(
      12,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      13,
      f
    );
  }
  f = message.getGatewayOptions();
  if (f.length > 0) {
    writer.writeString(
      14,
      f
    );
  }
  f = message.getMasterOptions();
  if (f.length > 0) {
    writer.writeString(
      15,
      f
    );
  }
  f = message.getNodeOptions();
  if (f.length > 0) {
    writer.writeString(
      16,
      f
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      17,
      f
    );
  }
  f = message.getParametersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      18,
      f
    );
  }
  f = message.getDefaultSshPort();
  if (f !== 0) {
    writer.writeUint32(
      19,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional ClusterComplexity complexity = 2;
 * @return {!proto.ClusterComplexity}
 */
proto.ClusterCreateRequest.prototype.getComplexity = function() {
  return /** @type {!proto.ClusterComplexity} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {!proto.ClusterComplexity} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setComplexity = function(value) {
  return jspb.Message.setProto3EnumField(this, 2, value);
};


/**
 * optional ClusterFlavor flavor = 3;
 * @return {!proto.ClusterFlavor}
 */
proto.ClusterCreateRequest.prototype.getFlavor = function() {
  return /** @type {!proto.ClusterFlavor} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.ClusterFlavor} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setFlavor = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional bool keep_on_failure = 4;
 * @return {boolean}
 */
proto.ClusterCreateRequest.prototype.getKeepOnFailure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 4, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setKeepOnFailure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 4, value);
};


/**
 * optional string cidr = 5;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * repeated string disabled = 6;
 * @return {!Array<string>}
 */
proto.ClusterCreateRequest.prototype.getDisabledList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 6));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setDisabledList = function(value) {
  return jspb.Message.setField(this, 6, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.addDisabled = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 6, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.clearDisabledList = function() {
  return this.setDisabledList([]);
};


/**
 * optional string os = 7;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getOs = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setOs = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string global_sizing = 8;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getGlobalSizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setGlobalSizing = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * optional string gateway_sizing = 9;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getGatewaySizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 9, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setGatewaySizing = function(value) {
  return jspb.Message.setProto3StringField(this, 9, value);
};


/**
 * optional string master_sizing = 10;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getMasterSizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 10, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setMasterSizing = function(value) {
  return jspb.Message.setProto3StringField(this, 10, value);
};


/**
 * optional string node_sizing = 11;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getNodeSizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 11, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setNodeSizing = function(value) {
  return jspb.Message.setProto3StringField(this, 11, value);
};


/**
 * optional string domain = 12;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getDomain = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 12, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setDomain = function(value) {
  return jspb.Message.setProto3StringField(this, 12, value);
};


/**
 * optional string tenant_id = 13;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 13, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 13, value);
};


/**
 * optional string gateway_options = 14;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getGatewayOptions = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 14, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setGatewayOptions = function(value) {
  return jspb.Message.setProto3StringField(this, 14, value);
};


/**
 * optional string master_options = 15;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getMasterOptions = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 15, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setMasterOptions = function(value) {
  return jspb.Message.setProto3StringField(this, 15, value);
};


/**
 * optional string node_options = 16;
 * @return {string}
 */
proto.ClusterCreateRequest.prototype.getNodeOptions = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 16, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setNodeOptions = function(value) {
  return jspb.Message.setProto3StringField(this, 16, value);
};


/**
 * optional bool force = 17;
 * @return {boolean}
 */
proto.ClusterCreateRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 17, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 17, value);
};


/**
 * repeated string parameters = 18;
 * @return {!Array<string>}
 */
proto.ClusterCreateRequest.prototype.getParametersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 18));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setParametersList = function(value) {
  return jspb.Message.setField(this, 18, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.addParameters = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 18, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.clearParametersList = function() {
  return this.setParametersList([]);
};


/**
 * optional uint32 default_ssh_port = 19;
 * @return {number}
 */
proto.ClusterCreateRequest.prototype.getDefaultSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 19, 0));
};


/**
 * @param {number} value
 * @return {!proto.ClusterCreateRequest} returns this
 */
proto.ClusterCreateRequest.prototype.setDefaultSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 19, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterResizeRequest.repeatedFields_ = [8];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterResizeRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterResizeRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterResizeRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterResizeRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    count: jspb.Message.getFieldWithDefault(msg, 2, 0),
    nodeSizing: jspb.Message.getFieldWithDefault(msg, 3, ""),
    imageId: jspb.Message.getFieldWithDefault(msg, 4, ""),
    dryRun: jspb.Message.getBooleanFieldWithDefault(msg, 5, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 6, ""),
    keepOnFailure: jspb.Message.getBooleanFieldWithDefault(msg, 7, false),
    parametersList: (f = jspb.Message.getRepeatedField(msg, 8)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterResizeRequest}
 */
proto.ClusterResizeRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterResizeRequest;
  return proto.ClusterResizeRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterResizeRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterResizeRequest}
 */
proto.ClusterResizeRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setCount(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setNodeSizing(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setImageId(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDryRun(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 7:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setKeepOnFailure(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.addParameters(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterResizeRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterResizeRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterResizeRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterResizeRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getCount();
  if (f !== 0) {
    writer.writeInt32(
      2,
      f
    );
  }
  f = message.getNodeSizing();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getImageId();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getDryRun();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getKeepOnFailure();
  if (f) {
    writer.writeBool(
      7,
      f
    );
  }
  f = message.getParametersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      8,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.ClusterResizeRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional int32 count = 2;
 * @return {number}
 */
proto.ClusterResizeRequest.prototype.getCount = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {number} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setCount = function(value) {
  return jspb.Message.setProto3IntField(this, 2, value);
};


/**
 * optional string node_sizing = 3;
 * @return {string}
 */
proto.ClusterResizeRequest.prototype.getNodeSizing = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setNodeSizing = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string image_id = 4;
 * @return {string}
 */
proto.ClusterResizeRequest.prototype.getImageId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setImageId = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional bool dry_run = 5;
 * @return {boolean}
 */
proto.ClusterResizeRequest.prototype.getDryRun = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setDryRun = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};


/**
 * optional string tenant_id = 6;
 * @return {string}
 */
proto.ClusterResizeRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional bool keep_on_failure = 7;
 * @return {boolean}
 */
proto.ClusterResizeRequest.prototype.getKeepOnFailure = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 7, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setKeepOnFailure = function(value) {
  return jspb.Message.setProto3BooleanField(this, 7, value);
};


/**
 * repeated string parameters = 8;
 * @return {!Array<string>}
 */
proto.ClusterResizeRequest.prototype.getParametersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 8));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.setParametersList = function(value) {
  return jspb.Message.setField(this, 8, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.addParameters = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 8, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterResizeRequest} returns this
 */
proto.ClusterResizeRequest.prototype.clearParametersList = function() {
  return this.setParametersList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterDeleteRequest}
 */
proto.ClusterDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterDeleteRequest;
  return proto.ClusterDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterDeleteRequest}
 */
proto.ClusterDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.ClusterDeleteRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterDeleteRequest} returns this
 */
proto.ClusterDeleteRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.ClusterDeleteRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.ClusterDeleteRequest} returns this
 */
proto.ClusterDeleteRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * optional string tenant_id = 3;
 * @return {string}
 */
proto.ClusterDeleteRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterDeleteRequest} returns this
 */
proto.ClusterDeleteRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterIdentity.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterIdentity.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterIdentity} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterIdentity.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    complexity: jspb.Message.getFieldWithDefault(msg, 2, 0),
    flavor: jspb.Message.getFieldWithDefault(msg, 3, 0),
    adminPassword: jspb.Message.getFieldWithDefault(msg, 4, ""),
    privateKey: jspb.Message.getFieldWithDefault(msg, 5, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterIdentity}
 */
proto.ClusterIdentity.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterIdentity;
  return proto.ClusterIdentity.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterIdentity} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterIdentity}
 */
proto.ClusterIdentity.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {!proto.ClusterComplexity} */ (reader.readEnum());
      msg.setComplexity(value);
      break;
    case 3:
      var value = /** @type {!proto.ClusterFlavor} */ (reader.readEnum());
      msg.setFlavor(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setAdminPassword(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrivateKey(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterIdentity.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterIdentity.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterIdentity} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterIdentity.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getComplexity();
  if (f !== 0.0) {
    writer.writeEnum(
      2,
      f
    );
  }
  f = message.getFlavor();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getAdminPassword();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getPrivateKey();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.ClusterIdentity.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterIdentity} returns this
 */
proto.ClusterIdentity.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional ClusterComplexity complexity = 2;
 * @return {!proto.ClusterComplexity}
 */
proto.ClusterIdentity.prototype.getComplexity = function() {
  return /** @type {!proto.ClusterComplexity} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {!proto.ClusterComplexity} value
 * @return {!proto.ClusterIdentity} returns this
 */
proto.ClusterIdentity.prototype.setComplexity = function(value) {
  return jspb.Message.setProto3EnumField(this, 2, value);
};


/**
 * optional ClusterFlavor flavor = 3;
 * @return {!proto.ClusterFlavor}
 */
proto.ClusterIdentity.prototype.getFlavor = function() {
  return /** @type {!proto.ClusterFlavor} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.ClusterFlavor} value
 * @return {!proto.ClusterIdentity} returns this
 */
proto.ClusterIdentity.prototype.setFlavor = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional string admin_password = 4;
 * @return {string}
 */
proto.ClusterIdentity.prototype.getAdminPassword = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterIdentity} returns this
 */
proto.ClusterIdentity.prototype.setAdminPassword = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string private_key = 5;
 * @return {string}
 */
proto.ClusterIdentity.prototype.getPrivateKey = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterIdentity} returns this
 */
proto.ClusterIdentity.prototype.setPrivateKey = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterHostOptions.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterHostOptions.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterHostOptions} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterHostOptions.toObject = function(includeInstance, msg) {
  var f, obj = {
    sshPort: jspb.Message.getFieldWithDefault(msg, 1, 0),
    hostNamePattern: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterHostOptions}
 */
proto.ClusterHostOptions.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterHostOptions;
  return proto.ClusterHostOptions.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterHostOptions} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterHostOptions}
 */
proto.ClusterHostOptions.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setSshPort(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setHostNamePattern(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterHostOptions.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterHostOptions.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterHostOptions} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterHostOptions.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSshPort();
  if (f !== 0) {
    writer.writeUint32(
      1,
      f
    );
  }
  f = message.getHostNamePattern();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional uint32 ssh_port = 1;
 * @return {number}
 */
proto.ClusterHostOptions.prototype.getSshPort = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {number} value
 * @return {!proto.ClusterHostOptions} returns this
 */
proto.ClusterHostOptions.prototype.setSshPort = function(value) {
  return jspb.Message.setProto3IntField(this, 1, value);
};


/**
 * optional string host_name_pattern = 2;
 * @return {string}
 */
proto.ClusterHostOptions.prototype.getHostNamePattern = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterHostOptions} returns this
 */
proto.ClusterHostOptions.prototype.setHostNamePattern = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterDefaults.repeatedFields_ = [8];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterDefaults.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterDefaults.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterDefaults} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterDefaults.toObject = function(includeInstance, msg) {
  var f, obj = {
    gatewaySizing: (f = msg.getGatewaySizing()) && proto.HostSizing.toObject(includeInstance, f),
    masterSizing: (f = msg.getMasterSizing()) && proto.HostSizing.toObject(includeInstance, f),
    nodeSizing: (f = msg.getNodeSizing()) && proto.HostSizing.toObject(includeInstance, f),
    image: jspb.Message.getFieldWithDefault(msg, 4, ""),
    gatewayOptions: (f = msg.getGatewayOptions()) && proto.ClusterHostOptions.toObject(includeInstance, f),
    masterOptions: (f = msg.getMasterOptions()) && proto.ClusterHostOptions.toObject(includeInstance, f),
    nodeOptions: (f = msg.getNodeOptions()) && proto.ClusterHostOptions.toObject(includeInstance, f),
    featureParametersList: (f = jspb.Message.getRepeatedField(msg, 8)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterDefaults}
 */
proto.ClusterDefaults.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterDefaults;
  return proto.ClusterDefaults.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterDefaults} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterDefaults}
 */
proto.ClusterDefaults.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.HostSizing;
      reader.readMessage(value,proto.HostSizing.deserializeBinaryFromReader);
      msg.setGatewaySizing(value);
      break;
    case 2:
      var value = new proto.HostSizing;
      reader.readMessage(value,proto.HostSizing.deserializeBinaryFromReader);
      msg.setMasterSizing(value);
      break;
    case 3:
      var value = new proto.HostSizing;
      reader.readMessage(value,proto.HostSizing.deserializeBinaryFromReader);
      msg.setNodeSizing(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setImage(value);
      break;
    case 5:
      var value = new proto.ClusterHostOptions;
      reader.readMessage(value,proto.ClusterHostOptions.deserializeBinaryFromReader);
      msg.setGatewayOptions(value);
      break;
    case 6:
      var value = new proto.ClusterHostOptions;
      reader.readMessage(value,proto.ClusterHostOptions.deserializeBinaryFromReader);
      msg.setMasterOptions(value);
      break;
    case 7:
      var value = new proto.ClusterHostOptions;
      reader.readMessage(value,proto.ClusterHostOptions.deserializeBinaryFromReader);
      msg.setNodeOptions(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.addFeatureParameters(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterDefaults.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterDefaults.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterDefaults} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterDefaults.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGatewaySizing();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.HostSizing.serializeBinaryToWriter
    );
  }
  f = message.getMasterSizing();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.HostSizing.serializeBinaryToWriter
    );
  }
  f = message.getNodeSizing();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.HostSizing.serializeBinaryToWriter
    );
  }
  f = message.getImage();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getGatewayOptions();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.ClusterHostOptions.serializeBinaryToWriter
    );
  }
  f = message.getMasterOptions();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.ClusterHostOptions.serializeBinaryToWriter
    );
  }
  f = message.getNodeOptions();
  if (f != null) {
    writer.writeMessage(
      7,
      f,
      proto.ClusterHostOptions.serializeBinaryToWriter
    );
  }
  f = message.getFeatureParametersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      8,
      f
    );
  }
};


/**
 * optional HostSizing gateway_sizing = 1;
 * @return {?proto.HostSizing}
 */
proto.ClusterDefaults.prototype.getGatewaySizing = function() {
  return /** @type{?proto.HostSizing} */ (
    jspb.Message.getWrapperField(this, proto.HostSizing, 1));
};


/**
 * @param {?proto.HostSizing|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setGatewaySizing = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearGatewaySizing = function() {
  return this.setGatewaySizing(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasGatewaySizing = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional HostSizing master_sizing = 2;
 * @return {?proto.HostSizing}
 */
proto.ClusterDefaults.prototype.getMasterSizing = function() {
  return /** @type{?proto.HostSizing} */ (
    jspb.Message.getWrapperField(this, proto.HostSizing, 2));
};


/**
 * @param {?proto.HostSizing|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setMasterSizing = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearMasterSizing = function() {
  return this.setMasterSizing(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasMasterSizing = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional HostSizing node_sizing = 3;
 * @return {?proto.HostSizing}
 */
proto.ClusterDefaults.prototype.getNodeSizing = function() {
  return /** @type{?proto.HostSizing} */ (
    jspb.Message.getWrapperField(this, proto.HostSizing, 3));
};


/**
 * @param {?proto.HostSizing|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setNodeSizing = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearNodeSizing = function() {
  return this.setNodeSizing(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasNodeSizing = function() {
  return jspb.Message.getField(this, 3) != null;
};


/**
 * optional string Image = 4;
 * @return {string}
 */
proto.ClusterDefaults.prototype.getImage = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.setImage = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional ClusterHostOptions gateway_options = 5;
 * @return {?proto.ClusterHostOptions}
 */
proto.ClusterDefaults.prototype.getGatewayOptions = function() {
  return /** @type{?proto.ClusterHostOptions} */ (
    jspb.Message.getWrapperField(this, proto.ClusterHostOptions, 5));
};


/**
 * @param {?proto.ClusterHostOptions|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setGatewayOptions = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearGatewayOptions = function() {
  return this.setGatewayOptions(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasGatewayOptions = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional ClusterHostOptions master_options = 6;
 * @return {?proto.ClusterHostOptions}
 */
proto.ClusterDefaults.prototype.getMasterOptions = function() {
  return /** @type{?proto.ClusterHostOptions} */ (
    jspb.Message.getWrapperField(this, proto.ClusterHostOptions, 6));
};


/**
 * @param {?proto.ClusterHostOptions|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setMasterOptions = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearMasterOptions = function() {
  return this.setMasterOptions(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasMasterOptions = function() {
  return jspb.Message.getField(this, 6) != null;
};


/**
 * optional ClusterHostOptions node_options = 7;
 * @return {?proto.ClusterHostOptions}
 */
proto.ClusterDefaults.prototype.getNodeOptions = function() {
  return /** @type{?proto.ClusterHostOptions} */ (
    jspb.Message.getWrapperField(this, proto.ClusterHostOptions, 7));
};


/**
 * @param {?proto.ClusterHostOptions|undefined} value
 * @return {!proto.ClusterDefaults} returns this
*/
proto.ClusterDefaults.prototype.setNodeOptions = function(value) {
  return jspb.Message.setWrapperField(this, 7, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearNodeOptions = function() {
  return this.setNodeOptions(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterDefaults.prototype.hasNodeOptions = function() {
  return jspb.Message.getField(this, 7) != null;
};


/**
 * repeated string feature_parameters = 8;
 * @return {!Array<string>}
 */
proto.ClusterDefaults.prototype.getFeatureParametersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 8));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.setFeatureParametersList = function(value) {
  return jspb.Message.setField(this, 8, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.addFeatureParameters = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 8, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterDefaults} returns this
 */
proto.ClusterDefaults.prototype.clearFeatureParametersList = function() {
  return this.setFeatureParametersList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterControlplane.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterControlplane.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterControlplane} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterControlplane.toObject = function(includeInstance, msg) {
  var f, obj = {
    vip: (f = msg.getVip()) && proto.VirtualIp.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterControlplane}
 */
proto.ClusterControlplane.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterControlplane;
  return proto.ClusterControlplane.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterControlplane} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterControlplane}
 */
proto.ClusterControlplane.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.VirtualIp;
      reader.readMessage(value,proto.VirtualIp.deserializeBinaryFromReader);
      msg.setVip(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterControlplane.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterControlplane.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterControlplane} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterControlplane.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getVip();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.VirtualIp.serializeBinaryToWriter
    );
  }
};


/**
 * optional VirtualIp vip = 1;
 * @return {?proto.VirtualIp}
 */
proto.ClusterControlplane.prototype.getVip = function() {
  return /** @type{?proto.VirtualIp} */ (
    jspb.Message.getWrapperField(this, proto.VirtualIp, 1));
};


/**
 * @param {?proto.VirtualIp|undefined} value
 * @return {!proto.ClusterControlplane} returns this
*/
proto.ClusterControlplane.prototype.setVip = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterControlplane} returns this
 */
proto.ClusterControlplane.prototype.clearVip = function() {
  return this.setVip(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterControlplane.prototype.hasVip = function() {
  return jspb.Message.getField(this, 1) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterComposite.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterComposite.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterComposite.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterComposite} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterComposite.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantsList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterComposite}
 */
proto.ClusterComposite.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterComposite;
  return proto.ClusterComposite.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterComposite} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterComposite}
 */
proto.ClusterComposite.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addTenants(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterComposite.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterComposite.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterComposite} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterComposite.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
};


/**
 * repeated string tenants = 1;
 * @return {!Array<string>}
 */
proto.ClusterComposite.prototype.getTenantsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.ClusterComposite} returns this
 */
proto.ClusterComposite.prototype.setTenantsList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.ClusterComposite} returns this
 */
proto.ClusterComposite.prototype.addTenants = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterComposite} returns this
 */
proto.ClusterComposite.prototype.clearTenantsList = function() {
  return this.setTenantsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterNetwork.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterNetwork.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterNetwork} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNetwork.toObject = function(includeInstance, msg) {
  var f, obj = {
    networkId: jspb.Message.getFieldWithDefault(msg, 1, ""),
    cidr: jspb.Message.getFieldWithDefault(msg, 2, ""),
    domain: jspb.Message.getFieldWithDefault(msg, 3, ""),
    gatewayId: jspb.Message.getFieldWithDefault(msg, 4, ""),
    gatewayIp: jspb.Message.getFieldWithDefault(msg, 5, ""),
    secondaryGatewayId: jspb.Message.getFieldWithDefault(msg, 6, ""),
    secondaryGatewayIp: jspb.Message.getFieldWithDefault(msg, 7, ""),
    defaultRouteIp: jspb.Message.getFieldWithDefault(msg, 8, ""),
    primaryPublicIp: jspb.Message.getFieldWithDefault(msg, 9, ""),
    secondaryPublicIp: jspb.Message.getFieldWithDefault(msg, 10, ""),
    endpointIp: jspb.Message.getFieldWithDefault(msg, 11, ""),
    subnetId: jspb.Message.getFieldWithDefault(msg, 14, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterNetwork}
 */
proto.ClusterNetwork.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterNetwork;
  return proto.ClusterNetwork.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterNetwork} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterNetwork}
 */
proto.ClusterNetwork.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setNetworkId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setCidr(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setDomain(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewayId(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setGatewayIp(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setSecondaryGatewayId(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setSecondaryGatewayIp(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setDefaultRouteIp(value);
      break;
    case 9:
      var value = /** @type {string} */ (reader.readString());
      msg.setPrimaryPublicIp(value);
      break;
    case 10:
      var value = /** @type {string} */ (reader.readString());
      msg.setSecondaryPublicIp(value);
      break;
    case 11:
      var value = /** @type {string} */ (reader.readString());
      msg.setEndpointIp(value);
      break;
    case 14:
      var value = /** @type {string} */ (reader.readString());
      msg.setSubnetId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterNetwork.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterNetwork.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterNetwork} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNetwork.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetworkId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getCidr();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getDomain();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getGatewayId();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getGatewayIp();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getSecondaryGatewayId();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getSecondaryGatewayIp();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getDefaultRouteIp();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
  f = message.getPrimaryPublicIp();
  if (f.length > 0) {
    writer.writeString(
      9,
      f
    );
  }
  f = message.getSecondaryPublicIp();
  if (f.length > 0) {
    writer.writeString(
      10,
      f
    );
  }
  f = message.getEndpointIp();
  if (f.length > 0) {
    writer.writeString(
      11,
      f
    );
  }
  f = message.getSubnetId();
  if (f.length > 0) {
    writer.writeString(
      14,
      f
    );
  }
};


/**
 * optional string network_id = 1;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getNetworkId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setNetworkId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string cidr = 2;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getCidr = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setCidr = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string domain = 3;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getDomain = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setDomain = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string gateway_id = 4;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getGatewayId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setGatewayId = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string gateway_ip = 5;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getGatewayIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setGatewayIp = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string secondary_gateway_id = 6;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getSecondaryGatewayId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setSecondaryGatewayId = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string secondary_gateway_ip = 7;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getSecondaryGatewayIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setSecondaryGatewayIp = function(value) {
  return jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string default_route_ip = 8;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getDefaultRouteIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setDefaultRouteIp = function(value) {
  return jspb.Message.setProto3StringField(this, 8, value);
};


/**
 * optional string primary_public_ip = 9;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getPrimaryPublicIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 9, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setPrimaryPublicIp = function(value) {
  return jspb.Message.setProto3StringField(this, 9, value);
};


/**
 * optional string secondary_public_ip = 10;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getSecondaryPublicIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 10, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setSecondaryPublicIp = function(value) {
  return jspb.Message.setProto3StringField(this, 10, value);
};


/**
 * optional string endpoint_ip = 11;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getEndpointIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 11, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setEndpointIp = function(value) {
  return jspb.Message.setProto3StringField(this, 11, value);
};


/**
 * optional string subnet_id = 14;
 * @return {string}
 */
proto.ClusterNetwork.prototype.getSubnetId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 14, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNetwork} returns this
 */
proto.ClusterNetwork.prototype.setSubnetId = function(value) {
  return jspb.Message.setProto3StringField(this, 14, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterResponse.repeatedFields_ = [3,4];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    identity: (f = msg.getIdentity()) && proto.ClusterIdentity.toObject(includeInstance, f),
    network: (f = msg.getNetwork()) && proto.ClusterNetwork.toObject(includeInstance, f),
    mastersList: jspb.Message.toObjectList(msg.getMastersList(),
    proto.Host.toObject, includeInstance),
    nodesList: jspb.Message.toObjectList(msg.getNodesList(),
    proto.Host.toObject, includeInstance),
    disabledFeatures: (f = msg.getDisabledFeatures()) && proto.FeatureListResponse.toObject(includeInstance, f),
    installedFeatures: (f = msg.getInstalledFeatures()) && proto.FeatureListResponse.toObject(includeInstance, f),
    defaults: (f = msg.getDefaults()) && proto.ClusterDefaults.toObject(includeInstance, f),
    state: jspb.Message.getFieldWithDefault(msg, 8, 0),
    composite: (f = msg.getComposite()) && proto.ClusterComposite.toObject(includeInstance, f),
    controlplane: (f = msg.getControlplane()) && proto.ClusterControlplane.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterResponse}
 */
proto.ClusterResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterResponse;
  return proto.ClusterResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterResponse}
 */
proto.ClusterResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.ClusterIdentity;
      reader.readMessage(value,proto.ClusterIdentity.deserializeBinaryFromReader);
      msg.setIdentity(value);
      break;
    case 2:
      var value = new proto.ClusterNetwork;
      reader.readMessage(value,proto.ClusterNetwork.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 3:
      var value = new proto.Host;
      reader.readMessage(value,proto.Host.deserializeBinaryFromReader);
      msg.addMasters(value);
      break;
    case 4:
      var value = new proto.Host;
      reader.readMessage(value,proto.Host.deserializeBinaryFromReader);
      msg.addNodes(value);
      break;
    case 5:
      var value = new proto.FeatureListResponse;
      reader.readMessage(value,proto.FeatureListResponse.deserializeBinaryFromReader);
      msg.setDisabledFeatures(value);
      break;
    case 6:
      var value = new proto.FeatureListResponse;
      reader.readMessage(value,proto.FeatureListResponse.deserializeBinaryFromReader);
      msg.setInstalledFeatures(value);
      break;
    case 7:
      var value = new proto.ClusterDefaults;
      reader.readMessage(value,proto.ClusterDefaults.deserializeBinaryFromReader);
      msg.setDefaults(value);
      break;
    case 8:
      var value = /** @type {!proto.ClusterState} */ (reader.readEnum());
      msg.setState(value);
      break;
    case 9:
      var value = new proto.ClusterComposite;
      reader.readMessage(value,proto.ClusterComposite.deserializeBinaryFromReader);
      msg.setComposite(value);
      break;
    case 10:
      var value = new proto.ClusterControlplane;
      reader.readMessage(value,proto.ClusterControlplane.deserializeBinaryFromReader);
      msg.setControlplane(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getIdentity();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.ClusterIdentity.serializeBinaryToWriter
    );
  }
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.ClusterNetwork.serializeBinaryToWriter
    );
  }
  f = message.getMastersList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      3,
      f,
      proto.Host.serializeBinaryToWriter
    );
  }
  f = message.getNodesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      4,
      f,
      proto.Host.serializeBinaryToWriter
    );
  }
  f = message.getDisabledFeatures();
  if (f != null) {
    writer.writeMessage(
      5,
      f,
      proto.FeatureListResponse.serializeBinaryToWriter
    );
  }
  f = message.getInstalledFeatures();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.FeatureListResponse.serializeBinaryToWriter
    );
  }
  f = message.getDefaults();
  if (f != null) {
    writer.writeMessage(
      7,
      f,
      proto.ClusterDefaults.serializeBinaryToWriter
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      8,
      f
    );
  }
  f = message.getComposite();
  if (f != null) {
    writer.writeMessage(
      9,
      f,
      proto.ClusterComposite.serializeBinaryToWriter
    );
  }
  f = message.getControlplane();
  if (f != null) {
    writer.writeMessage(
      10,
      f,
      proto.ClusterControlplane.serializeBinaryToWriter
    );
  }
};


/**
 * optional ClusterIdentity identity = 1;
 * @return {?proto.ClusterIdentity}
 */
proto.ClusterResponse.prototype.getIdentity = function() {
  return /** @type{?proto.ClusterIdentity} */ (
    jspb.Message.getWrapperField(this, proto.ClusterIdentity, 1));
};


/**
 * @param {?proto.ClusterIdentity|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setIdentity = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearIdentity = function() {
  return this.setIdentity(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasIdentity = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional ClusterNetwork network = 2;
 * @return {?proto.ClusterNetwork}
 */
proto.ClusterResponse.prototype.getNetwork = function() {
  return /** @type{?proto.ClusterNetwork} */ (
    jspb.Message.getWrapperField(this, proto.ClusterNetwork, 2));
};


/**
 * @param {?proto.ClusterNetwork|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * repeated Host masters = 3;
 * @return {!Array<!proto.Host>}
 */
proto.ClusterResponse.prototype.getMastersList = function() {
  return /** @type{!Array<!proto.Host>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Host, 3));
};


/**
 * @param {!Array<!proto.Host>} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setMastersList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 3, value);
};


/**
 * @param {!proto.Host=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Host}
 */
proto.ClusterResponse.prototype.addMasters = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 3, opt_value, proto.Host, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearMastersList = function() {
  return this.setMastersList([]);
};


/**
 * repeated Host nodes = 4;
 * @return {!Array<!proto.Host>}
 */
proto.ClusterResponse.prototype.getNodesList = function() {
  return /** @type{!Array<!proto.Host>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Host, 4));
};


/**
 * @param {!Array<!proto.Host>} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setNodesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 4, value);
};


/**
 * @param {!proto.Host=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Host}
 */
proto.ClusterResponse.prototype.addNodes = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 4, opt_value, proto.Host, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearNodesList = function() {
  return this.setNodesList([]);
};


/**
 * optional FeatureListResponse disabled_features = 5;
 * @return {?proto.FeatureListResponse}
 */
proto.ClusterResponse.prototype.getDisabledFeatures = function() {
  return /** @type{?proto.FeatureListResponse} */ (
    jspb.Message.getWrapperField(this, proto.FeatureListResponse, 5));
};


/**
 * @param {?proto.FeatureListResponse|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setDisabledFeatures = function(value) {
  return jspb.Message.setWrapperField(this, 5, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearDisabledFeatures = function() {
  return this.setDisabledFeatures(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasDisabledFeatures = function() {
  return jspb.Message.getField(this, 5) != null;
};


/**
 * optional FeatureListResponse installed_features = 6;
 * @return {?proto.FeatureListResponse}
 */
proto.ClusterResponse.prototype.getInstalledFeatures = function() {
  return /** @type{?proto.FeatureListResponse} */ (
    jspb.Message.getWrapperField(this, proto.FeatureListResponse, 6));
};


/**
 * @param {?proto.FeatureListResponse|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setInstalledFeatures = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearInstalledFeatures = function() {
  return this.setInstalledFeatures(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasInstalledFeatures = function() {
  return jspb.Message.getField(this, 6) != null;
};


/**
 * optional ClusterDefaults defaults = 7;
 * @return {?proto.ClusterDefaults}
 */
proto.ClusterResponse.prototype.getDefaults = function() {
  return /** @type{?proto.ClusterDefaults} */ (
    jspb.Message.getWrapperField(this, proto.ClusterDefaults, 7));
};


/**
 * @param {?proto.ClusterDefaults|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setDefaults = function(value) {
  return jspb.Message.setWrapperField(this, 7, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearDefaults = function() {
  return this.setDefaults(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasDefaults = function() {
  return jspb.Message.getField(this, 7) != null;
};


/**
 * optional ClusterState state = 8;
 * @return {!proto.ClusterState}
 */
proto.ClusterResponse.prototype.getState = function() {
  return /** @type {!proto.ClusterState} */ (jspb.Message.getFieldWithDefault(this, 8, 0));
};


/**
 * @param {!proto.ClusterState} value
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 8, value);
};


/**
 * optional ClusterComposite composite = 9;
 * @return {?proto.ClusterComposite}
 */
proto.ClusterResponse.prototype.getComposite = function() {
  return /** @type{?proto.ClusterComposite} */ (
    jspb.Message.getWrapperField(this, proto.ClusterComposite, 9));
};


/**
 * @param {?proto.ClusterComposite|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setComposite = function(value) {
  return jspb.Message.setWrapperField(this, 9, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearComposite = function() {
  return this.setComposite(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasComposite = function() {
  return jspb.Message.getField(this, 9) != null;
};


/**
 * optional ClusterControlplane controlplane = 10;
 * @return {?proto.ClusterControlplane}
 */
proto.ClusterResponse.prototype.getControlplane = function() {
  return /** @type{?proto.ClusterControlplane} */ (
    jspb.Message.getWrapperField(this, proto.ClusterControlplane, 10));
};


/**
 * @param {?proto.ClusterControlplane|undefined} value
 * @return {!proto.ClusterResponse} returns this
*/
proto.ClusterResponse.prototype.setControlplane = function(value) {
  return jspb.Message.setWrapperField(this, 10, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterResponse} returns this
 */
proto.ClusterResponse.prototype.clearControlplane = function() {
  return this.setControlplane(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterResponse.prototype.hasControlplane = function() {
  return jspb.Message.getField(this, 10) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.ClusterNodeListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterNodeListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterNodeListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterNodeListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNodeListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    nodesList: jspb.Message.toObjectList(msg.getNodesList(),
    proto.Host.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterNodeListResponse}
 */
proto.ClusterNodeListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterNodeListResponse;
  return proto.ClusterNodeListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterNodeListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterNodeListResponse}
 */
proto.ClusterNodeListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Host;
      reader.readMessage(value,proto.Host.deserializeBinaryFromReader);
      msg.addNodes(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterNodeListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterNodeListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterNodeListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNodeListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNodesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.Host.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Host nodes = 1;
 * @return {!Array<!proto.Host>}
 */
proto.ClusterNodeListResponse.prototype.getNodesList = function() {
  return /** @type{!Array<!proto.Host>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.Host, 1));
};


/**
 * @param {!Array<!proto.Host>} value
 * @return {!proto.ClusterNodeListResponse} returns this
*/
proto.ClusterNodeListResponse.prototype.setNodesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.Host=} opt_value
 * @param {number=} opt_index
 * @return {!proto.Host}
 */
proto.ClusterNodeListResponse.prototype.addNodes = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.Host, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.ClusterNodeListResponse} returns this
 */
proto.ClusterNodeListResponse.prototype.clearNodesList = function() {
  return this.setNodesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.ClusterNodeRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.ClusterNodeRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.ClusterNodeRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNodeRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.ClusterNodeRequest}
 */
proto.ClusterNodeRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.ClusterNodeRequest;
  return proto.ClusterNodeRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.ClusterNodeRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.ClusterNodeRequest}
 */
proto.ClusterNodeRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.ClusterNodeRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.ClusterNodeRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.ClusterNodeRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.ClusterNodeRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.ClusterNodeRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.ClusterNodeRequest} returns this
 */
proto.ClusterNodeRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.ClusterNodeRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.ClusterNodeRequest} returns this
*/
proto.ClusterNodeRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.ClusterNodeRequest} returns this
 */
proto.ClusterNodeRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.ClusterNodeRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.FeatureResponse.repeatedFields_ = [4,5];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    fileName: jspb.Message.getFieldWithDefault(msg, 3, ""),
    requiredByList: (f = jspb.Message.getRepeatedField(msg, 4)) == null ? undefined : f,
    requiresList: (f = jspb.Message.getRepeatedField(msg, 5)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureResponse}
 */
proto.FeatureResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureResponse;
  return proto.FeatureResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureResponse}
 */
proto.FeatureResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setFileName(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.addRequiredBy(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.addRequires(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getFileName();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getRequiredByList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      4,
      f
    );
  }
  f = message.getRequiresList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      5,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.FeatureResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string file_name = 3;
 * @return {string}
 */
proto.FeatureResponse.prototype.getFileName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.setFileName = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * repeated string required_by = 4;
 * @return {!Array<string>}
 */
proto.FeatureResponse.prototype.getRequiredByList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 4));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.setRequiredByList = function(value) {
  return jspb.Message.setField(this, 4, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.addRequiredBy = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 4, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.clearRequiredByList = function() {
  return this.setRequiredByList([]);
};


/**
 * repeated string requires = 5;
 * @return {!Array<string>}
 */
proto.FeatureResponse.prototype.getRequiresList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 5));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.setRequiresList = function(value) {
  return jspb.Message.setField(this, 5, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.addRequires = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 5, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureResponse} returns this
 */
proto.FeatureResponse.prototype.clearRequiresList = function() {
  return this.setRequiresList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    targetType: jspb.Message.getFieldWithDefault(msg, 1, 0),
    targetRef: (f = msg.getTargetRef()) && proto.Reference.toObject(includeInstance, f),
    installedOnly: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureListRequest}
 */
proto.FeatureListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureListRequest;
  return proto.FeatureListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureListRequest}
 */
proto.FeatureListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!proto.FeatureTargetType} */ (reader.readEnum());
      msg.setTargetType(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setTargetRef(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setInstalledOnly(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTargetType();
  if (f !== 0.0) {
    writer.writeEnum(
      1,
      f
    );
  }
  f = message.getTargetRef();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getInstalledOnly();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional FeatureTargetType target_type = 1;
 * @return {!proto.FeatureTargetType}
 */
proto.FeatureListRequest.prototype.getTargetType = function() {
  return /** @type {!proto.FeatureTargetType} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {!proto.FeatureTargetType} value
 * @return {!proto.FeatureListRequest} returns this
 */
proto.FeatureListRequest.prototype.setTargetType = function(value) {
  return jspb.Message.setProto3EnumField(this, 1, value);
};


/**
 * optional Reference target_ref = 2;
 * @return {?proto.Reference}
 */
proto.FeatureListRequest.prototype.getTargetRef = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.FeatureListRequest} returns this
*/
proto.FeatureListRequest.prototype.setTargetRef = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.FeatureListRequest} returns this
 */
proto.FeatureListRequest.prototype.clearTargetRef = function() {
  return this.setTargetRef(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.FeatureListRequest.prototype.hasTargetRef = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional bool installed_only = 3;
 * @return {boolean}
 */
proto.FeatureListRequest.prototype.getInstalledOnly = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureListRequest} returns this
 */
proto.FeatureListRequest.prototype.setInstalledOnly = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.FeatureListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    featuresList: jspb.Message.toObjectList(msg.getFeaturesList(),
    proto.FeatureResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureListResponse}
 */
proto.FeatureListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureListResponse;
  return proto.FeatureListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureListResponse}
 */
proto.FeatureListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.FeatureResponse;
      reader.readMessage(value,proto.FeatureResponse.deserializeBinaryFromReader);
      msg.addFeatures(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getFeaturesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.FeatureResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated FeatureResponse features = 1;
 * @return {!Array<!proto.FeatureResponse>}
 */
proto.FeatureListResponse.prototype.getFeaturesList = function() {
  return /** @type{!Array<!proto.FeatureResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.FeatureResponse, 1));
};


/**
 * @param {!Array<!proto.FeatureResponse>} value
 * @return {!proto.FeatureListResponse} returns this
*/
proto.FeatureListResponse.prototype.setFeaturesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.FeatureResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.FeatureResponse}
 */
proto.FeatureListResponse.prototype.addFeatures = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.FeatureResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureListResponse} returns this
 */
proto.FeatureListResponse.prototype.clearFeaturesList = function() {
  return this.setFeaturesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureDetailRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureDetailRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureDetailRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureDetailRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    targetType: jspb.Message.getFieldWithDefault(msg, 1, 0),
    targetRef: (f = msg.getTargetRef()) && proto.Reference.toObject(includeInstance, f),
    name: jspb.Message.getFieldWithDefault(msg, 3, ""),
    embedded: jspb.Message.getBooleanFieldWithDefault(msg, 4, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureDetailRequest}
 */
proto.FeatureDetailRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureDetailRequest;
  return proto.FeatureDetailRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureDetailRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureDetailRequest}
 */
proto.FeatureDetailRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!proto.FeatureTargetType} */ (reader.readEnum());
      msg.setTargetType(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setTargetRef(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 4:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setEmbedded(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureDetailRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureDetailRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureDetailRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureDetailRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTargetType();
  if (f !== 0.0) {
    writer.writeEnum(
      1,
      f
    );
  }
  f = message.getTargetRef();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getEmbedded();
  if (f) {
    writer.writeBool(
      4,
      f
    );
  }
};


/**
 * optional FeatureTargetType target_type = 1;
 * @return {!proto.FeatureTargetType}
 */
proto.FeatureDetailRequest.prototype.getTargetType = function() {
  return /** @type {!proto.FeatureTargetType} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/**
 * @param {!proto.FeatureTargetType} value
 * @return {!proto.FeatureDetailRequest} returns this
 */
proto.FeatureDetailRequest.prototype.setTargetType = function(value) {
  return jspb.Message.setProto3EnumField(this, 1, value);
};


/**
 * optional Reference target_ref = 2;
 * @return {?proto.Reference}
 */
proto.FeatureDetailRequest.prototype.getTargetRef = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.FeatureDetailRequest} returns this
*/
proto.FeatureDetailRequest.prototype.setTargetRef = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.FeatureDetailRequest} returns this
 */
proto.FeatureDetailRequest.prototype.clearTargetRef = function() {
  return this.setTargetRef(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.FeatureDetailRequest.prototype.hasTargetRef = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional string name = 3;
 * @return {string}
 */
proto.FeatureDetailRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.FeatureDetailRequest} returns this
 */
proto.FeatureDetailRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional bool embedded = 4;
 * @return {boolean}
 */
proto.FeatureDetailRequest.prototype.getEmbedded = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 4, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureDetailRequest} returns this
 */
proto.FeatureDetailRequest.prototype.setEmbedded = function(value) {
  return jspb.Message.setProto3BooleanField(this, 4, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.FeatureDetailResponse.repeatedFields_ = [3,4];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureDetailResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureDetailResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureDetailResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureDetailResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    eligible: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    installed: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    dependenciesList: (f = jspb.Message.getRepeatedField(msg, 3)) == null ? undefined : f,
    parametersList: (f = jspb.Message.getRepeatedField(msg, 4)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureDetailResponse}
 */
proto.FeatureDetailResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureDetailResponse;
  return proto.FeatureDetailResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureDetailResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureDetailResponse}
 */
proto.FeatureDetailResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setEligible(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setInstalled(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.addDependencies(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.addParameters(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureDetailResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureDetailResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureDetailResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureDetailResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getEligible();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getInstalled();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getDependenciesList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      3,
      f
    );
  }
  f = message.getParametersList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      4,
      f
    );
  }
};


/**
 * optional bool eligible = 1;
 * @return {boolean}
 */
proto.FeatureDetailResponse.prototype.getEligible = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.setEligible = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional bool installed = 2;
 * @return {boolean}
 */
proto.FeatureDetailResponse.prototype.getInstalled = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.setInstalled = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * repeated string dependencies = 3;
 * @return {!Array<string>}
 */
proto.FeatureDetailResponse.prototype.getDependenciesList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 3));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.setDependenciesList = function(value) {
  return jspb.Message.setField(this, 3, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.addDependencies = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 3, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.clearDependenciesList = function() {
  return this.setDependenciesList([]);
};


/**
 * repeated string parameters = 4;
 * @return {!Array<string>}
 */
proto.FeatureDetailResponse.prototype.getParametersList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 4));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.setParametersList = function(value) {
  return jspb.Message.setField(this, 4, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.addParameters = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 4, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureDetailResponse} returns this
 */
proto.FeatureDetailResponse.prototype.clearParametersList = function() {
  return this.setParametersList([]);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.FeatureExportResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureExportResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureExportResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureExportResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureExportResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    exportList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureExportResponse}
 */
proto.FeatureExportResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureExportResponse;
  return proto.FeatureExportResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureExportResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureExportResponse}
 */
proto.FeatureExportResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addExport(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureExportResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureExportResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureExportResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureExportResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getExportList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
};


/**
 * repeated string export = 1;
 * @return {!Array<string>}
 */
proto.FeatureExportResponse.prototype.getExportList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.FeatureExportResponse} returns this
 */
proto.FeatureExportResponse.prototype.setExportList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.FeatureExportResponse} returns this
 */
proto.FeatureExportResponse.prototype.addExport = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.FeatureExportResponse} returns this
 */
proto.FeatureExportResponse.prototype.clearExportList = function() {
  return this.setExportList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureSettings.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureSettings.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureSettings} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureSettings.toObject = function(includeInstance, msg) {
  var f, obj = {
    skipProxy: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    serialize: jspb.Message.getBooleanFieldWithDefault(msg, 2, false),
    ignoreFeatureRequirements: jspb.Message.getBooleanFieldWithDefault(msg, 3, false),
    ignoreSizingRequirements: jspb.Message.getBooleanFieldWithDefault(msg, 4, false),
    addUnconditionally: jspb.Message.getBooleanFieldWithDefault(msg, 5, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureSettings}
 */
proto.FeatureSettings.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureSettings;
  return proto.FeatureSettings.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureSettings} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureSettings}
 */
proto.FeatureSettings.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setSkipProxy(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setSerialize(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setIgnoreFeatureRequirements(value);
      break;
    case 4:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setIgnoreSizingRequirements(value);
      break;
    case 5:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAddUnconditionally(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureSettings.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureSettings.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureSettings} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureSettings.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSkipProxy();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getSerialize();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
  f = message.getIgnoreFeatureRequirements();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
  f = message.getIgnoreSizingRequirements();
  if (f) {
    writer.writeBool(
      4,
      f
    );
  }
  f = message.getAddUnconditionally();
  if (f) {
    writer.writeBool(
      5,
      f
    );
  }
};


/**
 * optional bool skip_proxy = 1;
 * @return {boolean}
 */
proto.FeatureSettings.prototype.getSkipProxy = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureSettings} returns this
 */
proto.FeatureSettings.prototype.setSkipProxy = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional bool serialize = 2;
 * @return {boolean}
 */
proto.FeatureSettings.prototype.getSerialize = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureSettings} returns this
 */
proto.FeatureSettings.prototype.setSerialize = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * optional bool ignore_feature_requirements = 3;
 * @return {boolean}
 */
proto.FeatureSettings.prototype.getIgnoreFeatureRequirements = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureSettings} returns this
 */
proto.FeatureSettings.prototype.setIgnoreFeatureRequirements = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};


/**
 * optional bool ignore_sizing_requirements = 4;
 * @return {boolean}
 */
proto.FeatureSettings.prototype.getIgnoreSizingRequirements = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 4, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureSettings} returns this
 */
proto.FeatureSettings.prototype.setIgnoreSizingRequirements = function(value) {
  return jspb.Message.setProto3BooleanField(this, 4, value);
};


/**
 * optional bool add_unconditionally = 5;
 * @return {boolean}
 */
proto.FeatureSettings.prototype.getAddUnconditionally = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 5, false));
};


/**
 * @param {boolean} value
 * @return {!proto.FeatureSettings} returns this
 */
proto.FeatureSettings.prototype.setAddUnconditionally = function(value) {
  return jspb.Message.setProto3BooleanField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.FeatureActionRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.FeatureActionRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.FeatureActionRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureActionRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantId: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    targetType: jspb.Message.getFieldWithDefault(msg, 3, 0),
    targetRef: (f = msg.getTargetRef()) && proto.Reference.toObject(includeInstance, f),
    variablesMap: (f = msg.getVariablesMap()) ? f.toObject(includeInstance, undefined) : [],
    settings: (f = msg.getSettings()) && proto.FeatureSettings.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.FeatureActionRequest}
 */
proto.FeatureActionRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.FeatureActionRequest;
  return proto.FeatureActionRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.FeatureActionRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.FeatureActionRequest}
 */
proto.FeatureActionRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {!proto.FeatureTargetType} */ (reader.readEnum());
      msg.setTargetType(value);
      break;
    case 4:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setTargetRef(value);
      break;
    case 5:
      var value = msg.getVariablesMap();
      reader.readMessage(value, function(message, reader) {
        jspb.Map.deserializeBinary(message, reader, jspb.BinaryReader.prototype.readString, jspb.BinaryReader.prototype.readString, null, "", "");
         });
      break;
    case 6:
      var value = new proto.FeatureSettings;
      reader.readMessage(value,proto.FeatureSettings.deserializeBinaryFromReader);
      msg.setSettings(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.FeatureActionRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.FeatureActionRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.FeatureActionRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.FeatureActionRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getTargetType();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getTargetRef();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getVariablesMap(true);
  if (f && f.getLength() > 0) {
    f.serializeBinary(5, writer, jspb.BinaryWriter.prototype.writeString, jspb.BinaryWriter.prototype.writeString);
  }
  f = message.getSettings();
  if (f != null) {
    writer.writeMessage(
      6,
      f,
      proto.FeatureSettings.serializeBinaryToWriter
    );
  }
};


/**
 * optional string tenant_id = 1;
 * @return {string}
 */
proto.FeatureActionRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.FeatureActionRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional FeatureTargetType target_type = 3;
 * @return {!proto.FeatureTargetType}
 */
proto.FeatureActionRequest.prototype.getTargetType = function() {
  return /** @type {!proto.FeatureTargetType} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.FeatureTargetType} value
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.setTargetType = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional Reference target_ref = 4;
 * @return {?proto.Reference}
 */
proto.FeatureActionRequest.prototype.getTargetRef = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 4));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.FeatureActionRequest} returns this
*/
proto.FeatureActionRequest.prototype.setTargetRef = function(value) {
  return jspb.Message.setWrapperField(this, 4, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.clearTargetRef = function() {
  return this.setTargetRef(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.FeatureActionRequest.prototype.hasTargetRef = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * map<string, string> variables = 5;
 * @param {boolean=} opt_noLazyCreate Do not create the map if
 * empty, instead returning `undefined`
 * @return {!jspb.Map<string,string>}
 */
proto.FeatureActionRequest.prototype.getVariablesMap = function(opt_noLazyCreate) {
  return /** @type {!jspb.Map<string,string>} */ (
      jspb.Message.getMapField(this, 5, opt_noLazyCreate,
      null));
};


/**
 * Clears values from the map. The map will be non-null.
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.clearVariablesMap = function() {
  this.getVariablesMap().clear();
  return this;};


/**
 * optional FeatureSettings settings = 6;
 * @return {?proto.FeatureSettings}
 */
proto.FeatureActionRequest.prototype.getSettings = function() {
  return /** @type{?proto.FeatureSettings} */ (
    jspb.Message.getWrapperField(this, proto.FeatureSettings, 6));
};


/**
 * @param {?proto.FeatureSettings|undefined} value
 * @return {!proto.FeatureActionRequest} returns this
*/
proto.FeatureActionRequest.prototype.setSettings = function(value) {
  return jspb.Message.setWrapperField(this, 6, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.FeatureActionRequest} returns this
 */
proto.FeatureActionRequest.prototype.clearSettings = function() {
  return this.setSettings(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.FeatureActionRequest.prototype.hasSettings = function() {
  return jspb.Message.getField(this, 6) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SecurityGroupRule.repeatedFields_ = [1,8];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupRule.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupRule.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupRule} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRule.toObject = function(includeInstance, msg) {
  var f, obj = {
    idsList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f,
    description: jspb.Message.getFieldWithDefault(msg, 2, ""),
    etherType: jspb.Message.getFieldWithDefault(msg, 3, 0),
    direction: jspb.Message.getFieldWithDefault(msg, 4, 0),
    protocol: jspb.Message.getFieldWithDefault(msg, 5, ""),
    portFrom: jspb.Message.getFieldWithDefault(msg, 6, 0),
    portTo: jspb.Message.getFieldWithDefault(msg, 7, 0),
    involvedList: (f = jspb.Message.getRepeatedField(msg, 8)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupRule}
 */
proto.SecurityGroupRule.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupRule;
  return proto.SecurityGroupRule.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupRule} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupRule}
 */
proto.SecurityGroupRule.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addIds(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setDescription(value);
      break;
    case 3:
      var value = /** @type {!proto.SecurityGroupRuleEtherType} */ (reader.readEnum());
      msg.setEtherType(value);
      break;
    case 4:
      var value = /** @type {!proto.SecurityGroupRuleDirection} */ (reader.readEnum());
      msg.setDirection(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setProtocol(value);
      break;
    case 6:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setPortFrom(value);
      break;
    case 7:
      var value = /** @type {number} */ (reader.readInt32());
      msg.setPortTo(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.addInvolved(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupRule.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupRule.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupRule} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRule.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getIdsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
  f = message.getDescription();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getEtherType();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
  f = message.getDirection();
  if (f !== 0.0) {
    writer.writeEnum(
      4,
      f
    );
  }
  f = message.getProtocol();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getPortFrom();
  if (f !== 0) {
    writer.writeInt32(
      6,
      f
    );
  }
  f = message.getPortTo();
  if (f !== 0) {
    writer.writeInt32(
      7,
      f
    );
  }
  f = message.getInvolvedList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      8,
      f
    );
  }
};


/**
 * repeated string ids = 1;
 * @return {!Array<string>}
 */
proto.SecurityGroupRule.prototype.getIdsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setIdsList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.addIds = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.clearIdsList = function() {
  return this.setIdsList([]);
};


/**
 * optional string description = 2;
 * @return {string}
 */
proto.SecurityGroupRule.prototype.getDescription = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setDescription = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional SecurityGroupRuleEtherType ether_type = 3;
 * @return {!proto.SecurityGroupRuleEtherType}
 */
proto.SecurityGroupRule.prototype.getEtherType = function() {
  return /** @type {!proto.SecurityGroupRuleEtherType} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.SecurityGroupRuleEtherType} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setEtherType = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};


/**
 * optional SecurityGroupRuleDirection direction = 4;
 * @return {!proto.SecurityGroupRuleDirection}
 */
proto.SecurityGroupRule.prototype.getDirection = function() {
  return /** @type {!proto.SecurityGroupRuleDirection} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {!proto.SecurityGroupRuleDirection} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setDirection = function(value) {
  return jspb.Message.setProto3EnumField(this, 4, value);
};


/**
 * optional string protocol = 5;
 * @return {string}
 */
proto.SecurityGroupRule.prototype.getProtocol = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setProtocol = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional int32 port_from = 6;
 * @return {number}
 */
proto.SecurityGroupRule.prototype.getPortFrom = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 6, 0));
};


/**
 * @param {number} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setPortFrom = function(value) {
  return jspb.Message.setProto3IntField(this, 6, value);
};


/**
 * optional int32 port_to = 7;
 * @return {number}
 */
proto.SecurityGroupRule.prototype.getPortTo = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 7, 0));
};


/**
 * @param {number} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setPortTo = function(value) {
  return jspb.Message.setProto3IntField(this, 7, value);
};


/**
 * repeated string involved = 8;
 * @return {!Array<string>}
 */
proto.SecurityGroupRule.prototype.getInvolvedList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 8));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.setInvolvedList = function(value) {
  return jspb.Message.setField(this, 8, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.addInvolved = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 8, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupRule} returns this
 */
proto.SecurityGroupRule.prototype.clearInvolvedList = function() {
  return this.setInvolvedList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupRuleRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupRuleRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupRuleRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRuleRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    group: (f = msg.getGroup()) && proto.Reference.toObject(includeInstance, f),
    rule: (f = msg.getRule()) && proto.SecurityGroupRule.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupRuleRequest}
 */
proto.SecurityGroupRuleRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupRuleRequest;
  return proto.SecurityGroupRuleRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupRuleRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupRuleRequest}
 */
proto.SecurityGroupRuleRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setGroup(value);
      break;
    case 2:
      var value = new proto.SecurityGroupRule;
      reader.readMessage(value,proto.SecurityGroupRule.deserializeBinaryFromReader);
      msg.setRule(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupRuleRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupRuleRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupRuleRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRuleRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGroup();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getRule();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.SecurityGroupRule.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference group = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupRuleRequest.prototype.getGroup = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupRuleRequest} returns this
*/
proto.SecurityGroupRuleRequest.prototype.setGroup = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupRuleRequest} returns this
 */
proto.SecurityGroupRuleRequest.prototype.clearGroup = function() {
  return this.setGroup(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupRuleRequest.prototype.hasGroup = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional SecurityGroupRule rule = 2;
 * @return {?proto.SecurityGroupRule}
 */
proto.SecurityGroupRuleRequest.prototype.getRule = function() {
  return /** @type{?proto.SecurityGroupRule} */ (
    jspb.Message.getWrapperField(this, proto.SecurityGroupRule, 2));
};


/**
 * @param {?proto.SecurityGroupRule|undefined} value
 * @return {!proto.SecurityGroupRuleRequest} returns this
*/
proto.SecurityGroupRuleRequest.prototype.setRule = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupRuleRequest} returns this
 */
proto.SecurityGroupRuleRequest.prototype.clearRule = function() {
  return this.setRule(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupRuleRequest.prototype.hasRule = function() {
  return jspb.Message.getField(this, 2) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupRuleDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupRuleDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRuleDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    group: (f = msg.getGroup()) && proto.Reference.toObject(includeInstance, f),
    rule: (f = msg.getRule()) && proto.SecurityGroupRule.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupRuleDeleteRequest}
 */
proto.SecurityGroupRuleDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupRuleDeleteRequest;
  return proto.SecurityGroupRuleDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupRuleDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupRuleDeleteRequest}
 */
proto.SecurityGroupRuleDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setGroup(value);
      break;
    case 2:
      var value = new proto.SecurityGroupRule;
      reader.readMessage(value,proto.SecurityGroupRule.deserializeBinaryFromReader);
      msg.setRule(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupRuleDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupRuleDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupRuleDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGroup();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getRule();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.SecurityGroupRule.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference group = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.getGroup = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupRuleDeleteRequest} returns this
*/
proto.SecurityGroupRuleDeleteRequest.prototype.setGroup = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupRuleDeleteRequest} returns this
 */
proto.SecurityGroupRuleDeleteRequest.prototype.clearGroup = function() {
  return this.setGroup(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.hasGroup = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional SecurityGroupRule rule = 2;
 * @return {?proto.SecurityGroupRule}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.getRule = function() {
  return /** @type{?proto.SecurityGroupRule} */ (
    jspb.Message.getWrapperField(this, proto.SecurityGroupRule, 2));
};


/**
 * @param {?proto.SecurityGroupRule|undefined} value
 * @return {!proto.SecurityGroupRuleDeleteRequest} returns this
*/
proto.SecurityGroupRuleDeleteRequest.prototype.setRule = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupRuleDeleteRequest} returns this
 */
proto.SecurityGroupRuleDeleteRequest.prototype.clearRule = function() {
  return this.setRule(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupRuleDeleteRequest.prototype.hasRule = function() {
  return jspb.Message.getField(this, 2) != null;
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SecurityGroupCreateRequest.repeatedFields_ = [4];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    description: jspb.Message.getFieldWithDefault(msg, 3, ""),
    rulesList: jspb.Message.toObjectList(msg.getRulesList(),
    proto.SecurityGroupRule.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupCreateRequest}
 */
proto.SecurityGroupCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupCreateRequest;
  return proto.SecurityGroupCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupCreateRequest}
 */
proto.SecurityGroupCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setDescription(value);
      break;
    case 4:
      var value = new proto.SecurityGroupRule;
      reader.readMessage(value,proto.SecurityGroupRule.deserializeBinaryFromReader);
      msg.addRules(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getDescription();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getRulesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      4,
      f,
      proto.SecurityGroupRule.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference network = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupCreateRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupCreateRequest} returns this
*/
proto.SecurityGroupCreateRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupCreateRequest} returns this
 */
proto.SecurityGroupCreateRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupCreateRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.SecurityGroupCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupCreateRequest} returns this
 */
proto.SecurityGroupCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string description = 3;
 * @return {string}
 */
proto.SecurityGroupCreateRequest.prototype.getDescription = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupCreateRequest} returns this
 */
proto.SecurityGroupCreateRequest.prototype.setDescription = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * repeated SecurityGroupRule rules = 4;
 * @return {!Array<!proto.SecurityGroupRule>}
 */
proto.SecurityGroupCreateRequest.prototype.getRulesList = function() {
  return /** @type{!Array<!proto.SecurityGroupRule>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.SecurityGroupRule, 4));
};


/**
 * @param {!Array<!proto.SecurityGroupRule>} value
 * @return {!proto.SecurityGroupCreateRequest} returns this
*/
proto.SecurityGroupCreateRequest.prototype.setRulesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 4, value);
};


/**
 * @param {!proto.SecurityGroupRule=} opt_value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupRule}
 */
proto.SecurityGroupCreateRequest.prototype.addRules = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 4, opt_value, proto.SecurityGroupRule, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupCreateRequest} returns this
 */
proto.SecurityGroupCreateRequest.prototype.clearRulesList = function() {
  return this.setRulesList([]);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SecurityGroupResponse.repeatedFields_ = [4];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    description: jspb.Message.getFieldWithDefault(msg, 3, ""),
    rulesList: jspb.Message.toObjectList(msg.getRulesList(),
    proto.SecurityGroupRule.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupResponse}
 */
proto.SecurityGroupResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupResponse;
  return proto.SecurityGroupResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupResponse}
 */
proto.SecurityGroupResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setDescription(value);
      break;
    case 4:
      var value = new proto.SecurityGroupRule;
      reader.readMessage(value,proto.SecurityGroupRule.deserializeBinaryFromReader);
      msg.addRules(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getDescription();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getRulesList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      4,
      f,
      proto.SecurityGroupRule.serializeBinaryToWriter
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.SecurityGroupResponse.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupResponse} returns this
 */
proto.SecurityGroupResponse.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.SecurityGroupResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupResponse} returns this
 */
proto.SecurityGroupResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string description = 3;
 * @return {string}
 */
proto.SecurityGroupResponse.prototype.getDescription = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupResponse} returns this
 */
proto.SecurityGroupResponse.prototype.setDescription = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * repeated SecurityGroupRule rules = 4;
 * @return {!Array<!proto.SecurityGroupRule>}
 */
proto.SecurityGroupResponse.prototype.getRulesList = function() {
  return /** @type{!Array<!proto.SecurityGroupRule>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.SecurityGroupRule, 4));
};


/**
 * @param {!Array<!proto.SecurityGroupRule>} value
 * @return {!proto.SecurityGroupResponse} returns this
*/
proto.SecurityGroupResponse.prototype.setRulesList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 4, value);
};


/**
 * @param {!proto.SecurityGroupRule=} opt_value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupRule}
 */
proto.SecurityGroupResponse.prototype.addRules = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 4, opt_value, proto.SecurityGroupRule, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupResponse} returns this
 */
proto.SecurityGroupResponse.prototype.clearRulesList = function() {
  return this.setRulesList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupListRequest}
 */
proto.SecurityGroupListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupListRequest;
  return proto.SecurityGroupListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupListRequest}
 */
proto.SecurityGroupListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.SecurityGroupListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SecurityGroupListRequest} returns this
 */
proto.SecurityGroupListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SecurityGroupListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    securityGroupsList: jspb.Message.toObjectList(msg.getSecurityGroupsList(),
    proto.SecurityGroupResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupListResponse}
 */
proto.SecurityGroupListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupListResponse;
  return proto.SecurityGroupListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupListResponse}
 */
proto.SecurityGroupListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.SecurityGroupResponse;
      reader.readMessage(value,proto.SecurityGroupResponse.deserializeBinaryFromReader);
      msg.addSecurityGroups(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSecurityGroupsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.SecurityGroupResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated SecurityGroupResponse security_groups = 1;
 * @return {!Array<!proto.SecurityGroupResponse>}
 */
proto.SecurityGroupListResponse.prototype.getSecurityGroupsList = function() {
  return /** @type{!Array<!proto.SecurityGroupResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.SecurityGroupResponse, 1));
};


/**
 * @param {!Array<!proto.SecurityGroupResponse>} value
 * @return {!proto.SecurityGroupListResponse} returns this
*/
proto.SecurityGroupListResponse.prototype.setSecurityGroupsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.SecurityGroupResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupResponse}
 */
proto.SecurityGroupListResponse.prototype.addSecurityGroups = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.SecurityGroupResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupListResponse} returns this
 */
proto.SecurityGroupListResponse.prototype.clearSecurityGroupsList = function() {
  return this.setSecurityGroupsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupHostBindRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupHostBindRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupHostBindRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupHostBindRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    group: (f = msg.getGroup()) && proto.Reference.toObject(includeInstance, f),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    state: jspb.Message.getFieldWithDefault(msg, 3, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupHostBindRequest}
 */
proto.SecurityGroupHostBindRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupHostBindRequest;
  return proto.SecurityGroupHostBindRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupHostBindRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupHostBindRequest}
 */
proto.SecurityGroupHostBindRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setGroup(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 3:
      var value = /** @type {!proto.SecurityGroupState} */ (reader.readEnum());
      msg.setState(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupHostBindRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupHostBindRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupHostBindRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupHostBindRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGroup();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      3,
      f
    );
  }
};


/**
 * optional Reference group = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupHostBindRequest.prototype.getGroup = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupHostBindRequest} returns this
*/
proto.SecurityGroupHostBindRequest.prototype.setGroup = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupHostBindRequest} returns this
 */
proto.SecurityGroupHostBindRequest.prototype.clearGroup = function() {
  return this.setGroup(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupHostBindRequest.prototype.hasGroup = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.SecurityGroupHostBindRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupHostBindRequest} returns this
*/
proto.SecurityGroupHostBindRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupHostBindRequest} returns this
 */
proto.SecurityGroupHostBindRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupHostBindRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional SecurityGroupState state = 3;
 * @return {!proto.SecurityGroupState}
 */
proto.SecurityGroupHostBindRequest.prototype.getState = function() {
  return /** @type {!proto.SecurityGroupState} */ (jspb.Message.getFieldWithDefault(this, 3, 0));
};


/**
 * @param {!proto.SecurityGroupState} value
 * @return {!proto.SecurityGroupHostBindRequest} returns this
 */
proto.SecurityGroupHostBindRequest.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupSubnetBindRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupSubnetBindRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupSubnetBindRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupSubnetBindRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    group: (f = msg.getGroup()) && proto.Reference.toObject(includeInstance, f),
    network: (f = msg.getNetwork()) && proto.Reference.toObject(includeInstance, f),
    subnet: (f = msg.getSubnet()) && proto.Reference.toObject(includeInstance, f),
    state: jspb.Message.getFieldWithDefault(msg, 4, 0)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupSubnetBindRequest}
 */
proto.SecurityGroupSubnetBindRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupSubnetBindRequest;
  return proto.SecurityGroupSubnetBindRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupSubnetBindRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupSubnetBindRequest}
 */
proto.SecurityGroupSubnetBindRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setGroup(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setNetwork(value);
      break;
    case 3:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setSubnet(value);
      break;
    case 4:
      var value = /** @type {!proto.SecurityGroupState} */ (reader.readEnum());
      msg.setState(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupSubnetBindRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupSubnetBindRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupSubnetBindRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupSubnetBindRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGroup();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getNetwork();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getSubnet();
  if (f != null) {
    writer.writeMessage(
      3,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getState();
  if (f !== 0.0) {
    writer.writeEnum(
      4,
      f
    );
  }
};


/**
 * optional Reference group = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupSubnetBindRequest.prototype.getGroup = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
*/
proto.SecurityGroupSubnetBindRequest.prototype.setGroup = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
 */
proto.SecurityGroupSubnetBindRequest.prototype.clearGroup = function() {
  return this.setGroup(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupSubnetBindRequest.prototype.hasGroup = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference network = 2;
 * @return {?proto.Reference}
 */
proto.SecurityGroupSubnetBindRequest.prototype.getNetwork = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
*/
proto.SecurityGroupSubnetBindRequest.prototype.setNetwork = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
 */
proto.SecurityGroupSubnetBindRequest.prototype.clearNetwork = function() {
  return this.setNetwork(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupSubnetBindRequest.prototype.hasNetwork = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional Reference subnet = 3;
 * @return {?proto.Reference}
 */
proto.SecurityGroupSubnetBindRequest.prototype.getSubnet = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 3));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
*/
proto.SecurityGroupSubnetBindRequest.prototype.setSubnet = function(value) {
  return jspb.Message.setWrapperField(this, 3, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
 */
proto.SecurityGroupSubnetBindRequest.prototype.clearSubnet = function() {
  return this.setSubnet(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupSubnetBindRequest.prototype.hasSubnet = function() {
  return jspb.Message.getField(this, 3) != null;
};


/**
 * optional SecurityGroupState state = 4;
 * @return {!proto.SecurityGroupState}
 */
proto.SecurityGroupSubnetBindRequest.prototype.getState = function() {
  return /** @type {!proto.SecurityGroupState} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/**
 * @param {!proto.SecurityGroupState} value
 * @return {!proto.SecurityGroupSubnetBindRequest} returns this
 */
proto.SecurityGroupSubnetBindRequest.prototype.setState = function(value) {
  return jspb.Message.setProto3EnumField(this, 4, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupBondsRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupBondsRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupBondsRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBondsRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    target: (f = msg.getTarget()) && proto.Reference.toObject(includeInstance, f),
    kind: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupBondsRequest}
 */
proto.SecurityGroupBondsRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupBondsRequest;
  return proto.SecurityGroupBondsRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupBondsRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupBondsRequest}
 */
proto.SecurityGroupBondsRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setTarget(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setKind(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupBondsRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupBondsRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupBondsRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBondsRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTarget();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getKind();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional Reference target = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupBondsRequest.prototype.getTarget = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupBondsRequest} returns this
*/
proto.SecurityGroupBondsRequest.prototype.setTarget = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupBondsRequest} returns this
 */
proto.SecurityGroupBondsRequest.prototype.clearTarget = function() {
  return this.setTarget(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupBondsRequest.prototype.hasTarget = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string kind = 2;
 * @return {string}
 */
proto.SecurityGroupBondsRequest.prototype.getKind = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupBondsRequest} returns this
 */
proto.SecurityGroupBondsRequest.prototype.setKind = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupBond.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupBond.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupBond} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBond.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    disabled: jspb.Message.getBooleanFieldWithDefault(msg, 3, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupBond}
 */
proto.SecurityGroupBond.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupBond;
  return proto.SecurityGroupBond.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupBond} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupBond}
 */
proto.SecurityGroupBond.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setDisabled(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupBond.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupBond.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupBond} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBond.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getDisabled();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.SecurityGroupBond.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupBond} returns this
 */
proto.SecurityGroupBond.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.SecurityGroupBond.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.SecurityGroupBond} returns this
 */
proto.SecurityGroupBond.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional bool disabled = 3;
 * @return {boolean}
 */
proto.SecurityGroupBond.prototype.getDisabled = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SecurityGroupBond} returns this
 */
proto.SecurityGroupBond.prototype.setDisabled = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.SecurityGroupBondsResponse.repeatedFields_ = [1,2];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupBondsResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupBondsResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupBondsResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBondsResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    hostsList: jspb.Message.toObjectList(msg.getHostsList(),
    proto.SecurityGroupBond.toObject, includeInstance),
    subnetsList: jspb.Message.toObjectList(msg.getSubnetsList(),
    proto.SecurityGroupBond.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupBondsResponse}
 */
proto.SecurityGroupBondsResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupBondsResponse;
  return proto.SecurityGroupBondsResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupBondsResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupBondsResponse}
 */
proto.SecurityGroupBondsResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.SecurityGroupBond;
      reader.readMessage(value,proto.SecurityGroupBond.deserializeBinaryFromReader);
      msg.addHosts(value);
      break;
    case 2:
      var value = new proto.SecurityGroupBond;
      reader.readMessage(value,proto.SecurityGroupBond.deserializeBinaryFromReader);
      msg.addSubnets(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupBondsResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupBondsResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupBondsResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupBondsResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHostsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.SecurityGroupBond.serializeBinaryToWriter
    );
  }
  f = message.getSubnetsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      2,
      f,
      proto.SecurityGroupBond.serializeBinaryToWriter
    );
  }
};


/**
 * repeated SecurityGroupBond hosts = 1;
 * @return {!Array<!proto.SecurityGroupBond>}
 */
proto.SecurityGroupBondsResponse.prototype.getHostsList = function() {
  return /** @type{!Array<!proto.SecurityGroupBond>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.SecurityGroupBond, 1));
};


/**
 * @param {!Array<!proto.SecurityGroupBond>} value
 * @return {!proto.SecurityGroupBondsResponse} returns this
*/
proto.SecurityGroupBondsResponse.prototype.setHostsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.SecurityGroupBond=} opt_value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupBond}
 */
proto.SecurityGroupBondsResponse.prototype.addHosts = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.SecurityGroupBond, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupBondsResponse} returns this
 */
proto.SecurityGroupBondsResponse.prototype.clearHostsList = function() {
  return this.setHostsList([]);
};


/**
 * repeated SecurityGroupBond subnets = 2;
 * @return {!Array<!proto.SecurityGroupBond>}
 */
proto.SecurityGroupBondsResponse.prototype.getSubnetsList = function() {
  return /** @type{!Array<!proto.SecurityGroupBond>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.SecurityGroupBond, 2));
};


/**
 * @param {!Array<!proto.SecurityGroupBond>} value
 * @return {!proto.SecurityGroupBondsResponse} returns this
*/
proto.SecurityGroupBondsResponse.prototype.setSubnetsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 2, value);
};


/**
 * @param {!proto.SecurityGroupBond=} opt_value
 * @param {number=} opt_index
 * @return {!proto.SecurityGroupBond}
 */
proto.SecurityGroupBondsResponse.prototype.addSubnets = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 2, opt_value, proto.SecurityGroupBond, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.SecurityGroupBondsResponse} returns this
 */
proto.SecurityGroupBondsResponse.prototype.clearSubnetsList = function() {
  return this.setSubnetsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.SecurityGroupDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.SecurityGroupDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.SecurityGroupDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    group: (f = msg.getGroup()) && proto.Reference.toObject(includeInstance, f),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.SecurityGroupDeleteRequest}
 */
proto.SecurityGroupDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.SecurityGroupDeleteRequest;
  return proto.SecurityGroupDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.SecurityGroupDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.SecurityGroupDeleteRequest}
 */
proto.SecurityGroupDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setGroup(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.SecurityGroupDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.SecurityGroupDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.SecurityGroupDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.SecurityGroupDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getGroup();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference group = 1;
 * @return {?proto.Reference}
 */
proto.SecurityGroupDeleteRequest.prototype.getGroup = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.SecurityGroupDeleteRequest} returns this
*/
proto.SecurityGroupDeleteRequest.prototype.setGroup = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.SecurityGroupDeleteRequest} returns this
 */
proto.SecurityGroupDeleteRequest.prototype.clearGroup = function() {
  return this.setGroup(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.SecurityGroupDeleteRequest.prototype.hasGroup = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.SecurityGroupDeleteRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.SecurityGroupDeleteRequest} returns this
 */
proto.SecurityGroupDeleteRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    tenantId: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    type: jspb.Message.getFieldWithDefault(msg, 3, ""),
    description: jspb.Message.getFieldWithDefault(msg, 4, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPCreateRequest}
 */
proto.PublicIPCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPCreateRequest;
  return proto.PublicIPCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPCreateRequest}
 */
proto.PublicIPCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setType(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setDescription(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getType();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getDescription();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
};


/**
 * optional string tenant_id = 1;
 * @return {string}
 */
proto.PublicIPCreateRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPCreateRequest} returns this
 */
proto.PublicIPCreateRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.PublicIPCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPCreateRequest} returns this
 */
proto.PublicIPCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string type = 3;
 * @return {string}
 */
proto.PublicIPCreateRequest.prototype.getType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPCreateRequest} returns this
 */
proto.PublicIPCreateRequest.prototype.setType = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string description = 4;
 * @return {string}
 */
proto.PublicIPCreateRequest.prototype.getDescription = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPCreateRequest} returns this
 */
proto.PublicIPCreateRequest.prototype.setDescription = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    type: jspb.Message.getFieldWithDefault(msg, 3, ""),
    description: jspb.Message.getFieldWithDefault(msg, 4, ""),
    ipAddress: jspb.Message.getFieldWithDefault(msg, 5, ""),
    macAddress: jspb.Message.getFieldWithDefault(msg, 6, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPResponse}
 */
proto.PublicIPResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPResponse;
  return proto.PublicIPResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPResponse}
 */
proto.PublicIPResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setType(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setDescription(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setIpAddress(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setMacAddress(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getType();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getDescription();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getIpAddress();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
  f = message.getMacAddress();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string type = 3;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getType = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setType = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string description = 4;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getDescription = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setDescription = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional string ip_address = 5;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getIpAddress = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setIpAddress = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};


/**
 * optional string mac_address = 6;
 * @return {string}
 */
proto.PublicIPResponse.prototype.getMacAddress = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPResponse} returns this
 */
proto.PublicIPResponse.prototype.setMacAddress = function(value) {
  return jspb.Message.setProto3StringField(this, 6, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    all: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPListRequest}
 */
proto.PublicIPListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPListRequest;
  return proto.PublicIPListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPListRequest}
 */
proto.PublicIPListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setAll(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getAll();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool all = 1;
 * @return {boolean}
 */
proto.PublicIPListRequest.prototype.getAll = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.PublicIPListRequest} returns this
 */
proto.PublicIPListRequest.prototype.setAll = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.PublicIPListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.PublicIPListRequest} returns this
 */
proto.PublicIPListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.PublicIPListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    publicIpsList: jspb.Message.toObjectList(msg.getPublicIpsList(),
    proto.PublicIPResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPListResponse}
 */
proto.PublicIPListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPListResponse;
  return proto.PublicIPListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPListResponse}
 */
proto.PublicIPListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.PublicIPResponse;
      reader.readMessage(value,proto.PublicIPResponse.deserializeBinaryFromReader);
      msg.addPublicIps(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getPublicIpsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.PublicIPResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated PublicIPResponse public_ips = 1;
 * @return {!Array<!proto.PublicIPResponse>}
 */
proto.PublicIPListResponse.prototype.getPublicIpsList = function() {
  return /** @type{!Array<!proto.PublicIPResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.PublicIPResponse, 1));
};


/**
 * @param {!Array<!proto.PublicIPResponse>} value
 * @return {!proto.PublicIPListResponse} returns this
*/
proto.PublicIPListResponse.prototype.setPublicIpsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.PublicIPResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.PublicIPResponse}
 */
proto.PublicIPListResponse.prototype.addPublicIps = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.PublicIPResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.PublicIPListResponse} returns this
 */
proto.PublicIPListResponse.prototype.clearPublicIpsList = function() {
  return this.setPublicIpsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPDeleteRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPDeleteRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPDeleteRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPDeleteRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    ip: (f = msg.getIp()) && proto.Reference.toObject(includeInstance, f),
    force: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPDeleteRequest}
 */
proto.PublicIPDeleteRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPDeleteRequest;
  return proto.PublicIPDeleteRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPDeleteRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPDeleteRequest}
 */
proto.PublicIPDeleteRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setIp(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setForce(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPDeleteRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPDeleteRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPDeleteRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPDeleteRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getIp();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getForce();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference ip = 1;
 * @return {?proto.Reference}
 */
proto.PublicIPDeleteRequest.prototype.getIp = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.PublicIPDeleteRequest} returns this
*/
proto.PublicIPDeleteRequest.prototype.setIp = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.PublicIPDeleteRequest} returns this
 */
proto.PublicIPDeleteRequest.prototype.clearIp = function() {
  return this.setIp(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.PublicIPDeleteRequest.prototype.hasIp = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool force = 2;
 * @return {boolean}
 */
proto.PublicIPDeleteRequest.prototype.getForce = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.PublicIPDeleteRequest} returns this
 */
proto.PublicIPDeleteRequest.prototype.setForce = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.PublicIPBindRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.PublicIPBindRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.PublicIPBindRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPBindRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    ip: (f = msg.getIp()) && proto.Reference.toObject(includeInstance, f),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.PublicIPBindRequest}
 */
proto.PublicIPBindRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.PublicIPBindRequest;
  return proto.PublicIPBindRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.PublicIPBindRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.PublicIPBindRequest}
 */
proto.PublicIPBindRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setIp(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.PublicIPBindRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.PublicIPBindRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.PublicIPBindRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.PublicIPBindRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getIp();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
};


/**
 * optional Reference ip = 1;
 * @return {?proto.Reference}
 */
proto.PublicIPBindRequest.prototype.getIp = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.PublicIPBindRequest} returns this
*/
proto.PublicIPBindRequest.prototype.setIp = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.PublicIPBindRequest} returns this
 */
proto.PublicIPBindRequest.prototype.clearIp = function() {
  return this.setIp(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.PublicIPBindRequest.prototype.hasIp = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.PublicIPBindRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.PublicIPBindRequest} returns this
*/
proto.PublicIPBindRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.PublicIPBindRequest} returns this
 */
proto.PublicIPBindRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.PublicIPBindRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelCreateRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelCreateRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelCreateRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelCreateRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    name: jspb.Message.getFieldWithDefault(msg, 1, ""),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, ""),
    hasDefault: jspb.Message.getBooleanFieldWithDefault(msg, 3, false),
    defaultValue: jspb.Message.getFieldWithDefault(msg, 4, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelCreateRequest}
 */
proto.LabelCreateRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelCreateRequest;
  return proto.LabelCreateRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelCreateRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelCreateRequest}
 */
proto.LabelCreateRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    case 3:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setHasDefault(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setDefaultValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelCreateRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelCreateRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelCreateRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelCreateRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getHasDefault();
  if (f) {
    writer.writeBool(
      3,
      f
    );
  }
  f = message.getDefaultValue();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
};


/**
 * optional string name = 1;
 * @return {string}
 */
proto.LabelCreateRequest.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelCreateRequest} returns this
 */
proto.LabelCreateRequest.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.LabelCreateRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelCreateRequest} returns this
 */
proto.LabelCreateRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional bool has_default = 3;
 * @return {boolean}
 */
proto.LabelCreateRequest.prototype.getHasDefault = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 3, false));
};


/**
 * @param {boolean} value
 * @return {!proto.LabelCreateRequest} returns this
 */
proto.LabelCreateRequest.prototype.setHasDefault = function(value) {
  return jspb.Message.setProto3BooleanField(this, 3, value);
};


/**
 * optional string default_value = 4;
 * @return {string}
 */
proto.LabelCreateRequest.prototype.getDefaultValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelCreateRequest} returns this
 */
proto.LabelCreateRequest.prototype.setDefaultValue = function(value) {
  return jspb.Message.setProto3StringField(this, 4, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelInspectRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelInspectRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelInspectRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelInspectRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    label: (f = msg.getLabel()) && proto.Reference.toObject(includeInstance, f),
    isTag: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelInspectRequest}
 */
proto.LabelInspectRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelInspectRequest;
  return proto.LabelInspectRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelInspectRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelInspectRequest}
 */
proto.LabelInspectRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setLabel(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setIsTag(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelInspectRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelInspectRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelInspectRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelInspectRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getLabel();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getIsTag();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference Label = 1;
 * @return {?proto.Reference}
 */
proto.LabelInspectRequest.prototype.getLabel = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.LabelInspectRequest} returns this
*/
proto.LabelInspectRequest.prototype.setLabel = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.LabelInspectRequest} returns this
 */
proto.LabelInspectRequest.prototype.clearLabel = function() {
  return this.setLabel(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.LabelInspectRequest.prototype.hasLabel = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool is_tag = 2;
 * @return {boolean}
 */
proto.LabelInspectRequest.prototype.getIsTag = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.LabelInspectRequest} returns this
 */
proto.LabelInspectRequest.prototype.setIsTag = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.LabelInspectResponse.repeatedFields_ = [3];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelInspectResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelInspectResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelInspectResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelInspectResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: jspb.Message.getFieldWithDefault(msg, 1, ""),
    name: jspb.Message.getFieldWithDefault(msg, 2, ""),
    hostsList: jspb.Message.toObjectList(msg.getHostsList(),
    proto.LabelHostResponse.toObject, includeInstance),
    hasDefault: jspb.Message.getBooleanFieldWithDefault(msg, 4, false),
    defaultValue: jspb.Message.getFieldWithDefault(msg, 5, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelInspectResponse}
 */
proto.LabelInspectResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelInspectResponse;
  return proto.LabelInspectResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelInspectResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelInspectResponse}
 */
proto.LabelInspectResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setName(value);
      break;
    case 3:
      var value = new proto.LabelHostResponse;
      reader.readMessage(value,proto.LabelHostResponse.deserializeBinaryFromReader);
      msg.addHosts(value);
      break;
    case 4:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setHasDefault(value);
      break;
    case 5:
      var value = /** @type {string} */ (reader.readString());
      msg.setDefaultValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelInspectResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelInspectResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelInspectResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelInspectResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getName();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getHostsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      3,
      f,
      proto.LabelHostResponse.serializeBinaryToWriter
    );
  }
  f = message.getHasDefault();
  if (f) {
    writer.writeBool(
      4,
      f
    );
  }
  f = message.getDefaultValue();
  if (f.length > 0) {
    writer.writeString(
      5,
      f
    );
  }
};


/**
 * optional string id = 1;
 * @return {string}
 */
proto.LabelInspectResponse.prototype.getId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelInspectResponse} returns this
 */
proto.LabelInspectResponse.prototype.setId = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string name = 2;
 * @return {string}
 */
proto.LabelInspectResponse.prototype.getName = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelInspectResponse} returns this
 */
proto.LabelInspectResponse.prototype.setName = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * repeated LabelHostResponse hosts = 3;
 * @return {!Array<!proto.LabelHostResponse>}
 */
proto.LabelInspectResponse.prototype.getHostsList = function() {
  return /** @type{!Array<!proto.LabelHostResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.LabelHostResponse, 3));
};


/**
 * @param {!Array<!proto.LabelHostResponse>} value
 * @return {!proto.LabelInspectResponse} returns this
*/
proto.LabelInspectResponse.prototype.setHostsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 3, value);
};


/**
 * @param {!proto.LabelHostResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.LabelHostResponse}
 */
proto.LabelInspectResponse.prototype.addHosts = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 3, opt_value, proto.LabelHostResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.LabelInspectResponse} returns this
 */
proto.LabelInspectResponse.prototype.clearHostsList = function() {
  return this.setHostsList([]);
};


/**
 * optional bool has_default = 4;
 * @return {boolean}
 */
proto.LabelInspectResponse.prototype.getHasDefault = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 4, false));
};


/**
 * @param {boolean} value
 * @return {!proto.LabelInspectResponse} returns this
 */
proto.LabelInspectResponse.prototype.setHasDefault = function(value) {
  return jspb.Message.setProto3BooleanField(this, 4, value);
};


/**
 * optional string default_value = 5;
 * @return {string}
 */
proto.LabelInspectResponse.prototype.getDefaultValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelInspectResponse} returns this
 */
proto.LabelInspectResponse.prototype.setDefaultValue = function(value) {
  return jspb.Message.setProto3StringField(this, 5, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelListRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelListRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelListRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelListRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    tags: jspb.Message.getBooleanFieldWithDefault(msg, 1, false),
    tenantId: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelListRequest}
 */
proto.LabelListRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelListRequest;
  return proto.LabelListRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelListRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelListRequest}
 */
proto.LabelListRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setTags(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setTenantId(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelListRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelListRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelListRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelListRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getTags();
  if (f) {
    writer.writeBool(
      1,
      f
    );
  }
  f = message.getTenantId();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional bool tags = 1;
 * @return {boolean}
 */
proto.LabelListRequest.prototype.getTags = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 1, false));
};


/**
 * @param {boolean} value
 * @return {!proto.LabelListRequest} returns this
 */
proto.LabelListRequest.prototype.setTags = function(value) {
  return jspb.Message.setProto3BooleanField(this, 1, value);
};


/**
 * optional string tenant_id = 2;
 * @return {string}
 */
proto.LabelListRequest.prototype.getTenantId = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelListRequest} returns this
 */
proto.LabelListRequest.prototype.setTenantId = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};



/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.LabelListResponse.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelListResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelListResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelListResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelListResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    labelsList: jspb.Message.toObjectList(msg.getLabelsList(),
    proto.LabelInspectResponse.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelListResponse}
 */
proto.LabelListResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelListResponse;
  return proto.LabelListResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelListResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelListResponse}
 */
proto.LabelListResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.LabelInspectResponse;
      reader.readMessage(value,proto.LabelInspectResponse.deserializeBinaryFromReader);
      msg.addLabels(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelListResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelListResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelListResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelListResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getLabelsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.LabelInspectResponse.serializeBinaryToWriter
    );
  }
};


/**
 * repeated LabelInspectResponse labels = 1;
 * @return {!Array<!proto.LabelInspectResponse>}
 */
proto.LabelListResponse.prototype.getLabelsList = function() {
  return /** @type{!Array<!proto.LabelInspectResponse>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.LabelInspectResponse, 1));
};


/**
 * @param {!Array<!proto.LabelInspectResponse>} value
 * @return {!proto.LabelListResponse} returns this
*/
proto.LabelListResponse.prototype.setLabelsList = function(value) {
  return jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.LabelInspectResponse=} opt_value
 * @param {number=} opt_index
 * @return {!proto.LabelInspectResponse}
 */
proto.LabelListResponse.prototype.addLabels = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.LabelInspectResponse, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.LabelListResponse} returns this
 */
proto.LabelListResponse.prototype.clearLabelsList = function() {
  return this.setLabelsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelHostResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelHostResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelHostResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelHostResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    value: jspb.Message.getFieldWithDefault(msg, 2, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelHostResponse}
 */
proto.LabelHostResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelHostResponse;
  return proto.LabelHostResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelHostResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelHostResponse}
 */
proto.LabelHostResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelHostResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelHostResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelHostResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelHostResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getValue();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.LabelHostResponse.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.LabelHostResponse} returns this
*/
proto.LabelHostResponse.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.LabelHostResponse} returns this
 */
proto.LabelHostResponse.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.LabelHostResponse.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional string value = 2;
 * @return {string}
 */
proto.LabelHostResponse.prototype.getValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelHostResponse} returns this
 */
proto.LabelHostResponse.prototype.setValue = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelBindRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelBindRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelBindRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelBindRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    label: (f = msg.getLabel()) && proto.Reference.toObject(includeInstance, f),
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    value: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelBindRequest}
 */
proto.LabelBindRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelBindRequest;
  return proto.LabelBindRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelBindRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelBindRequest}
 */
proto.LabelBindRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setLabel(value);
      break;
    case 2:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setValue(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelBindRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelBindRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelBindRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelBindRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getLabel();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      2,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getValue();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional Reference label = 1;
 * @return {?proto.Reference}
 */
proto.LabelBindRequest.prototype.getLabel = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.LabelBindRequest} returns this
*/
proto.LabelBindRequest.prototype.setLabel = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.LabelBindRequest} returns this
 */
proto.LabelBindRequest.prototype.clearLabel = function() {
  return this.setLabel(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.LabelBindRequest.prototype.hasLabel = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional Reference host = 2;
 * @return {?proto.Reference}
 */
proto.LabelBindRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 2));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.LabelBindRequest} returns this
*/
proto.LabelBindRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 2, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.LabelBindRequest} returns this
 */
proto.LabelBindRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.LabelBindRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 2) != null;
};


/**
 * optional string value = 3;
 * @return {string}
 */
proto.LabelBindRequest.prototype.getValue = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.LabelBindRequest} returns this
 */
proto.LabelBindRequest.prototype.setValue = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.LabelBoundsRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.LabelBoundsRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.LabelBoundsRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelBoundsRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
    host: (f = msg.getHost()) && proto.Reference.toObject(includeInstance, f),
    tags: jspb.Message.getBooleanFieldWithDefault(msg, 2, false)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.LabelBoundsRequest}
 */
proto.LabelBoundsRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.LabelBoundsRequest;
  return proto.LabelBoundsRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.LabelBoundsRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.LabelBoundsRequest}
 */
proto.LabelBoundsRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.Reference;
      reader.readMessage(value,proto.Reference.deserializeBinaryFromReader);
      msg.setHost(value);
      break;
    case 2:
      var value = /** @type {boolean} */ (reader.readBool());
      msg.setTags(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.LabelBoundsRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.LabelBoundsRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.LabelBoundsRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.LabelBoundsRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHost();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.Reference.serializeBinaryToWriter
    );
  }
  f = message.getTags();
  if (f) {
    writer.writeBool(
      2,
      f
    );
  }
};


/**
 * optional Reference host = 1;
 * @return {?proto.Reference}
 */
proto.LabelBoundsRequest.prototype.getHost = function() {
  return /** @type{?proto.Reference} */ (
    jspb.Message.getWrapperField(this, proto.Reference, 1));
};


/**
 * @param {?proto.Reference|undefined} value
 * @return {!proto.LabelBoundsRequest} returns this
*/
proto.LabelBoundsRequest.prototype.setHost = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.LabelBoundsRequest} returns this
 */
proto.LabelBoundsRequest.prototype.clearHost = function() {
  return this.setHost(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.LabelBoundsRequest.prototype.hasHost = function() {
  return jspb.Message.getField(this, 1) != null;
};


/**
 * optional bool tags = 2;
 * @return {boolean}
 */
proto.LabelBoundsRequest.prototype.getTags = function() {
  return /** @type {boolean} */ (jspb.Message.getBooleanFieldWithDefault(this, 2, false));
};


/**
 * @param {boolean} value
 * @return {!proto.LabelBoundsRequest} returns this
 */
proto.LabelBoundsRequest.prototype.setTags = function(value) {
  return jspb.Message.setProto3BooleanField(this, 2, value);
};


/**
 * @enum {number}
 */
proto.NetworkState = {
  NS_UNKNOWNSTATE: 0,
  NS_PHASE1: 1,
  NS_PHASE2: 2,
  NS_READY: 3,
  NS_NETWORKERROR: 4
};

/**
 * @enum {number}
 */
proto.SubnetState = {
  SS_UNKNOWNSTATE: 0,
  SS_PHASE1: 1,
  SS_PHASE2: 2,
  SS_READY: 3,
  SS_NETWORKERROR: 4
};

/**
 * @enum {number}
 */
proto.HostState = {
  HS_STOPPED: 0,
  HS_STARTING: 1,
  HS_STARTED: 2,
  HS_STOPPING: 3,
  HS_ERROR: 4,
  HS_TERMINATED: 5,
  HS_UNKNOWN: 6,
  HS_ANY: 7,
  HS_FAILED: 8,
  HS_DELETED: 9
};

/**
 * @enum {number}
 */
proto.VolumeSpeed = {
  VS_COLD: 0,
  VS_HDD: 1,
  VS_SSD: 2
};

/**
 * @enum {number}
 */
proto.ClusterState = {
  CS_UNKNOWN: 0,
  CS_NOMINAL: 1,
  CS_DEGRADED: 2,
  CS_STOPPED: 3,
  CS_INITIALIZING: 4,
  CS_CREATED: 5,
  CS_CREATING: 6,
  CS_ERROR: 7,
  CS_REMOVED: 8,
  CS_STOPPING: 9,
  CS_STARTING: 10
};

/**
 * @enum {number}
 */
proto.ClusterComplexity = {
  CC_UNKNOWN: 0,
  CC_SMALL: 1,
  CC_NORMAL: 2,
  CC_LARGE: 3
};

/**
 * @enum {number}
 */
proto.ClusterFlavor = {
  CF_UNKNOWN: 0,
  CF_BOH: 1,
  CF_K8S: 2
};

/**
 * @enum {number}
 */
proto.FeatureTargetType = {
  FT_ALL: 0,
  FT_HOST: 1,
  FT_CLUSTER: 2
};

/**
 * @enum {number}
 */
proto.SecurityGroupRuleDirection = {
  SGRD_UNKNOWN: 0,
  SGRD_INGRESS: 1,
  SGRD_EGRESS: 2
};

/**
 * @enum {number}
 */
proto.SecurityGroupRuleEtherType = {
  SGRET_UNKNOWN: 0,
  SGRET_IPV4: 4,
  SGRET_IPV6: 6
};

/**
 * @enum {number}
 */
proto.SecurityGroupState = {
  SGS_ALL: 0,
  SGS_ENABLED: 1,
  SGS_DISABLED: 2
};

goog.object.extend(exports, proto);
